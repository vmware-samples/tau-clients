#!/usr/bin/env python
# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import argparse
import configparser
import datetime
import io
import os
import random
import sys
import time
from typing import Dict
from typing import Generator
from typing import List
from typing import Optional

import tau_clients
import vt
from tau_clients import exceptions
from tau_clients import nsx_defender


INPUT_TYPE_FILE_HASH = "file-hash"

INPUT_TYPE_FILE_SAMPLE = "file-sample"


class WaitResultTimeout(Exception):
    """Exception when waiting for completion timeouts."""


def yield_completed_tasks(
    analysis_client: nsx_defender.AnalysisClient,
    submissions: List[Dict],
    start_timestamp: datetime.datetime,
    wait_completion_interval_seconds: float = 15.0,
    wait_completion_max_seconds: Optional[float] = None,
    wait_max_num_tries: int = 5,
) -> Generator[Dict, None, None]:
    """
    Returns a generator, which gives completed tasks as soon as they are ready.

    :param AnalysisClient analysis_client: the client
    :param list[dict] submissions: dictionary of submissions
    :param datetime.datetime start_timestamp: timestamp before the first submission has happened
    :param float wait_completion_max_seconds: don't wait for longer than this many seconds
    :param float wait_completion_interval_seconds: how long to wait between polls for completion
    :type start_timestamp: `datetime.datetime`
    :param int wait_max_num_tries: maximum number of tried
    :rtype: generator[dict]
    :return: generator that yields completed tasks
    :raises WaitResultTimeout: when waiting for results timed out
    """

    def _get_timeout_or_raise() -> float:
        end_completion_time = (
            time.time() + wait_completion_max_seconds
            if wait_completion_max_seconds is not None
            else None
        )
        sleep_timeout = wait_completion_interval_seconds
        if end_completion_time is not None:
            now = time.time()
            if now >= end_completion_time:
                raise WaitResultTimeout()
            if now + sleep_timeout > end_completion_time:
                sleep_timeout = end_completion_time - now
        return sleep_timeout

    attempts = 0
    pending_submissions = {x["task_uuid"]: x for x in submissions if "score" not in x}
    while pending_submissions:
        try:
            ret = analysis_client.get_completed(after=start_timestamp, include_score=True)
        except exceptions.CommunicationError:
            attempts += 1
            if attempts > wait_max_num_tries:
                raise
        else:
            attempts = 0
            start_timestamp = ret["before"]
            for task_uuid, score in ret["tasks"].items():
                try:
                    submission = pending_submissions[task_uuid]
                except KeyError:
                    continue
                submission["score"] = score
                del pending_submissions[task_uuid]
                yield submission
            if ret["more_results_available"]:
                continue
            if not pending_submissions:
                break
        time.sleep(_get_timeout_or_raise())
    print(f"Done waiting for completion of {len(submissions)} submissions")


def is_likely_binary(file_path: str) -> bool:
    """
    Return whether the file is likely to be binary.

    :param str file_path: the path to the file
    :rtype: bool
    :return: whether the file is likely not a text file
    """
    try:
        with open(file_path, "r") as f:  # pylint:disable=W1514
            for _ in f:
                break
            return False
    except UnicodeDecodeError:
        return True


def detect_input_type(input_bit) -> str:
    """
    Detect the input type.

    :param str input_bit: a file path or a hash-like string
    :rtype: bool
    :return: either 'INPUT_TYPE_FILE_SAMPLE' or 'INPUT_TYPE_FILE_HASH'
    :raises ValueError: if the input type could not be recognized
    """
    if os.path.isdir(input_bit):
        input_type = INPUT_TYPE_FILE_SAMPLE
    elif os.path.isfile(input_bit):
        if is_likely_binary(input_bit):
            input_type = INPUT_TYPE_FILE_SAMPLE
        else:
            input_type = INPUT_TYPE_FILE_HASH
    elif is_hash(input_bit):
        input_type = INPUT_TYPE_FILE_HASH
    else:
        raise ValueError("Specify the input type ('-t')")
    return input_type


def download_from_vt(client: vt.Client, file_hash: str) -> bytes:
    """
    Download file from VT.
    :param vt.Client client: the VT client
    :param str file_hash: the file hash
    :rtype: bytes
    :return: the downloaded data
    :raises ValueError: in case of any error
    """
    try:
        buffer = io.BytesIO()
        client.download_file(file_hash, buffer)
        buffer.seek(0, 0)
        return buffer.read()
    except (IOError, vt.APIError) as e:
        raise ValueError(str(e)) from e


def is_hash(input_bit: str) -> bool:
    """
    Return true whether this is an actual hash.

    :param str input_bit: the string to test
    :rtype: bool
    :return: whether the string is hash-like
    """
    hash_type = tau_clients.get_hash_type(input_bit)
    if not hash_type:
        return False
    else:
        try:
            int(input_bit, 16)
            return True
        except ValueError:
            return False


def get_file_hashes(file_path: str, limit: Optional[int] = None) -> List[str]:
    """
    Read all file hashes from a plaintext file.

    :param str file_path: the path to the file
    :param str|None limit: optional limit
    :rtype: list[str]
    :return: list of hashes
    """
    if not os.path.exists(file_path):
        return []
    file_hashes = set([])
    with open(file_path, "r") as data_file:  # pylint:disable=W1514
        data = data_file.readlines()
    for item in data:
        item = item.strip()
        if is_hash(item):
            file_hashes.add(item)
    # Shuffle deterministically
    file_hashes = sorted(file_hashes)[:limit]
    random.Random(4).shuffle(file_hashes)
    return file_hashes


def get_file_paths(
    dir_name: str,
    extension: Optional[str] = None,
    limit: Optional[int] = None,
) -> List[str]:
    """
    Return all absolute paths inside a directory

    :param str dir_name: the path to the directory
    :param str|None extension: optional extension filter
    :param str|None limit: optional limit
    :rtype: list[str]
    :return: list of file paths
    """
    if not os.path.exists(dir_name):
        return []
    if os.path.isfile(dir_name):
        file_paths = [os.path.abspath(dir_name)]
    else:
        file_paths = set(
            [
                os.path.abspath(os.path.join(dp, f))
                for dp, _, filenames in os.walk(dir_name)
                for f in filenames
                if f.endswith(extension or "")
            ]
        )
    # Shuffle deterministically
    file_paths = sorted(file_paths)[:limit]
    random.Random(4).shuffle(file_paths)
    return file_paths


def is_valid_config_file(file_path: str) -> str:
    """
    Validate the path to the configuration file.

    :param str file_path: the path to the config file
    :rtype: str
    :return: the validated file path
    :raises ValueError: if the path is not valid
    """
    if not os.path.isfile(file_path):
        raise ValueError(f"Invalid file path '{file_path}' for configuration file")
    return file_path


def main():
    """Submit all samples or hashes by downloading from VT first."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--config-file",
        dest="config_file",
        default="./data/tau_clients.ini",
        type=is_valid_config_file,
        help="read config from here",
    )
    parser.add_argument(
        "input_bits",
        metavar="input_bits",
        nargs="+",
        help="input file paths, or hashes",
    )
    parser.add_argument(
        "-b",
        "--bypass-cache",
        dest="bypass_cache",
        action="store_true",
        default=False,
        help="whether to bypass the cache",
    )
    parser.add_argument(
        "-t",
        "--input-type",
        choices=[
            INPUT_TYPE_FILE_HASH,
            INPUT_TYPE_FILE_SAMPLE,
        ],
        dest="input_type",
        default=None,
        help="what the input represents, file hashes or file paths (defaults to auto-detect)",
    )
    args = parser.parse_args()
    conf = configparser.ConfigParser()
    conf.read(args.config_file)

    try:
        vt_client = vt.Client(apikey=conf.get("vt", "apikey"))
    except configparser.Error:
        print("VT credentials not found. Hash submissions are disabled")
        vt_client = None

    # Parse and decode the input
    file_paths = []
    file_hashes = []
    for input_bit in args.input_bits:
        input_type = args.input_type
        if not input_type:
            input_type = detect_input_type(input_bit)
            print(f"Input '{input_bit}' is treated as {input_type}. Force using '-t' option")
        if input_type == INPUT_TYPE_FILE_HASH:
            if not vt_client:
                print(f"Hash submission '{input_bit}' requires VT credentials. Skipping.")
                continue
            if os.path.isfile(input_bit):
                file_hashes.extend(get_file_hashes(input_bit))
            elif is_hash(input_bit):
                print(f"Downloading '{input_bit}' from VT")
                file_hashes.append(input_bit)
        elif input_type == INPUT_TYPE_FILE_SAMPLE:
            file_paths.extend(get_file_paths(input_bit))
        else:
            raise ValueError("Unknown input type")
    print(f"Decoded input into {len(file_hashes)} file hashes and {len(file_paths)} samples")

    # Submit
    analysis_client = nsx_defender.AnalysisClient.from_conf(conf, "analysis")
    submission_start_ts = analysis_client.get_api_utc_timestamp()
    submissions = []
    task_to_source = {}
    for file_path in file_paths:
        with open(file_path, "rb") as f:
            try:
                ret = analysis_client.submit_file(f.read(), bypass_cache=args.bypass_cache)
                submissions.append(ret)
                task_to_source[ret["task_uuid"]] = file_path
            except exceptions.ApiError as ae:
                print(f"Error '{str(ae)}' when submitting file {file_path}")
    for file_hash in file_hashes:
        file_data = download_from_vt(vt_client, file_hash)
        try:
            ret = analysis_client.submit_file(file_data, bypass_cache=args.bypass_cache)
            submissions.append(ret)
            task_to_source[ret["task_uuid"]] = file_hash
        except exceptions.ApiError as ae:
            print(f"Error '{str(ae)}' when submitting file {file_hash}")
    if vt_client:
        vt_client.close()
    print(f"All files have been submitted ({len(submissions)} submissions)")

    # Wait for completion
    try:
        for submission in yield_completed_tasks(
            analysis_client,
            submissions,
            start_timestamp=submission_start_ts,
        ):
            task_uuid = submission.get("task_uuid")
            if not task_uuid:
                print(f"File '{task_to_source['task_uuid']}' was not submitted correctly")
    except KeyboardInterrupt:
        print("Waiting for results interrupted by user")

    print("Done")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python
# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import argparse
import configparser
import io
import sys

import tau_clients
import vt
from tau_clients import decoders
from tau_clients import exceptions
from tau_clients import nsx_defender


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


def main():
    """Submit all samples or hashes by downloading from VT first."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--config-file",
        dest="config_file",
        default="./data/tau_clients.ini",
        type=tau_clients.is_valid_config_file,
        help="read config from here",
    )
    parser.add_argument(
        "-b",
        "--bypass-cache",
        dest="bypass_cache",
        action="store_true",
        default=False,
        help="whether to bypass the cache",
    )
    decoders.InputTypeDecoder.add_arguments_to_parser(
        parser=parser,
        choices=[
            decoders.InputType.DIRECTORY,
            decoders.InputType.FILE_HASH,
            decoders.InputType.FILE,
        ],
    )
    args = parser.parse_args()
    conf = configparser.ConfigParser()
    conf.read(args.config_file)

    # Load the analysis client
    analysis_client = nsx_defender.AnalysisClient.from_conf(conf, "analysis")

    # Decode input type
    file_inputs, input_type = decoders.InputTypeDecoder().decode(
        arguments=args.input_bits,
        input_type=decoders.InputType(args.input_type),
        inspect_content=False,
    )

    # Parse the input
    vt_client = None
    file_paths = []
    file_hashes = []
    if input_type is decoders.InputType.FILE_HASH:
        try:
            vt_client = vt.Client(apikey=conf.get("vt", "apikey"))
        except configparser.Error:
            print("VT credentials not found. Hash submissions are disabled")
            return 1
        file_hashes.extend(file_inputs)
    elif input_type is decoders.InputType.FILE:
        for file_input in file_inputs:
            file_paths.extend(tau_clients.get_file_paths(file_input))
    else:
        raise ValueError("Unknown input type")
    print(f"Decoded input into {len(file_hashes)} file hashes and {len(file_paths)} samples")

    # Submit
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
        try:
            file_data = download_from_vt(vt_client, file_hash)
            ret = analysis_client.submit_file(file_data, bypass_cache=args.bypass_cache)
            submissions.append(ret)
            task_to_source[ret["task_uuid"]] = file_hash
        except ValueError as ve:
            print(f"Error '{str(ve)}' when downloading file {file_hash}")
        except exceptions.ApiError as ae:
            print(f"Error '{str(ae)}' when submitting file {file_hash}")
    if vt_client:
        vt_client.close()
    print(f"All files have been submitted ({len(submissions)} submissions)")

    # Wait for completion
    try:
        for submission in analysis_client.yield_completed_tasks(
            submissions=submissions,
            start_timestamp=submission_start_ts,
        ):
            task_uuid = submission.get("task_uuid")
            if not task_uuid:
                print(f"File '{task_to_source[task_uuid]}' was not submitted correctly")
            else:
                task_link = tau_clients.get_task_link(task_uuid, prefer_load_balancer=True)
                print(f"File '{task_to_source[task_uuid]}' finished analysis: {task_link}")
    except KeyboardInterrupt:
        print("Waiting for results interrupted by user")

    print("Done")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import argparse
import configparser
import io
import sys
import time
from typing import Generator
from typing import Tuple

import tau_clients
import vt
from tau_clients import decoders
from tau_clients import exceptions
from tau_clients import nsx_defender

# Sleep time in-between checks for pending submissions
DEFAULT_SLEEP_TIME = 5


def get_pending_submissions_count(analysis_client: nsx_defender.AbstractClientSubType) -> int:
    """Get the number of pending submissions while handling pagination."""
    nb_pending = 0
    ret = analysis_client.get_pending()
    nb_pending += len(ret["tasks"])
    while ret["more_results_available"] == 1:
        ret = analysis_client.get_pending(before=ret["resume"])
        nb_pending += len(ret["tasks"])
    return nb_pending


def wait_for_pending_submissions(
    analysis_client: nsx_defender.AbstractClientSubType,
    max_pending: int,
    sleep_time: int = DEFAULT_SLEEP_TIME,
) -> Generator[int, None, None]:
    """Wait until the number of pending submission reach a maximum value"""
    nb_pending = get_pending_submissions_count(analysis_client)
    while max_pending and nb_pending >= max_pending:
        yield nb_pending
        time.sleep(sleep_time)
        nb_pending = get_pending_submissions_count(analysis_client)


def download_from_vt(client: vt.Client, file_hash: str) -> bytes:
    """Download file from VT."""
    try:
        buffer = io.BytesIO()
        client.download_file(file_hash, buffer)
        buffer.seek(0, 0)
        return buffer.read()
    except (IOError, vt.APIError) as e:
        raise ValueError(str(e)) from e


def retry(times: int, errors: Tuple):
    """Retry Decorator."""

    def decorator(func):
        def new_func(*args, **kwargs):
            attempt = 0
            while attempt < times:
                try:
                    return func(*args, **kwargs)
                except errors as er:
                    print(
                        f"Exception '{str(er)}' when running {func} (attempt {attempt}/{times})"
                    )
                    attempt += 1
            return func(*args, **kwargs)

        return new_func

    return decorator


class RetryAnalysisClient(nsx_defender.AnalysisClient):
    """A simple client with some retrying logic."""

    @retry(times=5, errors=(exceptions.CommunicationError,))
    def submit_file(self, *args, **kwargs):
        """Override super method with a decorated one."""
        return super(RetryAnalysisClient, self).submit_file(*args, **kwargs)

    @retry(times=5, errors=(exceptions.CommunicationError,))
    def get_pending(self, *args, **kwargs):
        """Override super method with a decorated one."""
        return super(RetryAnalysisClient, self).get_pending(*args, **kwargs)


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
    parser.add_argument(
        "-p",
        "--bypass-prefilter",
        dest="bypass_prefilter",
        action="store_true",
        default=False,
        help="whether to bypass the prefilter",
    )
    parser.add_argument(
        "-d",
        "--delete-after-analysis",
        dest="delete_after_analysis",
        action="store_true",
        default=False,
        help="whether to delete the sample after analysis",
    )
    parser.add_argument(
        "-s",
        "--skip-first-n",
        dest="skip_first_n",
        default=0,
        type=int,
        help="the number of samples to skip",
    )
    parser.add_argument(
        "-w",
        "--max-pending-submissions",
        dest="max_pending_submissions",
        default=0,
        type=int,
        help="if set, specify the maximum number of pending submissions before submitting more",
    )
    parser.add_argument(
        "-e",
        "--sleep-in-between-submissions",
        dest="sleep_in_between_submissions",
        default=0,
        type=int,
        help="if set, wait the given number of second in-between submissions",
    )
    parser.add_argument(
        "-x",
        "--skip-waiting-for-completion",
        dest="skip_waiting_for_completion",
        action="store_true",
        default=False,
        help="if set, skip waiting for completion and only print the analysis links",
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
    analysis_client = RetryAnalysisClient.from_conf(conf, "analysis")

    # Decode input type
    file_inputs, input_type = decoders.InputTypeDecoder().decode(
        arguments=args.input_bits,
        input_type=decoders.InputType(args.input_type),
        inspect_content=False,
    )
    print(f"Decoded {len(file_inputs)} items (skipping first {args.skip_first_n})")
    file_inputs = file_inputs[args.skip_first_n :]

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
    for idx, file_path in enumerate(file_paths, start=1):
        resume_msg = f"(use '-s {args.skip_first_n + idx}' to resume from here)"
        with open(file_path, "rb") as f:
            try:
                if args.max_pending_submissions:
                    for nb_pending in wait_for_pending_submissions(
                        analysis_client=analysis_client,
                        max_pending=args.max_pending_submissions,
                    ):
                        print(
                            f"[{idx}/{len(file_paths)}] Waiting til pending submissions are below "
                            f"{args.max_pending_submissions} (currently {nb_pending})"
                        )
                else:
                    nb_pending = get_pending_submissions_count(analysis_client)
                ret = analysis_client.submit_file(
                    f.read(),
                    bypass_cache=args.bypass_cache,
                    bypass_prefilter=args.bypass_prefilter,
                    delete_after_analysis=args.delete_after_analysis,
                )
                submissions.append(ret)
                task_to_source[ret["task_uuid"]] = file_path
                print(
                    f"[{idx}/{len(file_paths)}] Submitted '{file_path}' successfully "
                    f"{resume_msg} (pending {nb_pending})"
                )
                if args.sleep_in_between_submissions:
                    # time.sleep(0) is not a no-op
                    time.sleep(args.sleep_in_between_submissions)
            except exceptions.ApiError as ae:
                print(f"Error '{str(ae)}' when submitting file {file_path}")
    for idx, file_hash in enumerate(file_hashes, start=1):
        resume_msg = f"(use '-s {args.skip_first_n + idx}' to resume from here)"
        try:
            file_data = download_from_vt(vt_client, file_hash)
            if args.max_pending_submissions:
                for nb_pending in wait_for_pending_submissions(
                    analysis_client=analysis_client,
                    max_pending=args.max_pending_submissions,
                ):
                    print(
                        f"[{idx}/{len(file_paths)}] Waiting until pending submissions are below "
                        f"{args.max_pending_submissions} (currently {nb_pending})"
                    )
            else:
                nb_pending = get_pending_submissions_count(analysis_client)
            if args.sleep_in_between_submissions:
                # time.sleep(0) is not a no-op
                time.sleep(args.sleep_in_between_submissions)
            ret = analysis_client.submit_file(
                file_data,
                bypass_cache=args.bypass_cache,
                bypass_prefilter=args.bypass_prefilter,
                delete_after_analysis=args.delete_after_analysis,
            )
            submissions.append(ret)
            task_to_source[ret["task_uuid"]] = file_hash
            print(
                f"[{idx}/{len(file_hashes)}] Download and submitted '{file_hash}' successfully "
                f"{resume_msg} (pending {nb_pending})"
            )
            if args.sleep_in_between_submissions:
                # time.sleep(0) is not a no-op
                time.sleep(args.sleep_in_between_submissions)
        except ValueError as ve:
            print(f"Error '{str(ve)}' when downloading file {file_hash}")
        except exceptions.ApiError as ae:
            print(f"Error '{str(ae)}' when submitting file {file_hash}")
    if vt_client:
        vt_client.close()
    print(f"All files have been submitted ({len(submissions)} submissions)")

    # Wait for completion
    if args.skip_waiting_for_completion:
        for submission in submissions:
            task_uuid = submission.get("task_uuid")
            task_link = tau_clients.get_task_link(task_uuid, prefer_load_balancer=True)
            print(f"File '{task_to_source[task_uuid]}' analysis link: {task_link}")
    else:
        try:
            for idx, submission in enumerate(
                analysis_client.yield_completed_tasks(
                    submissions=submissions,
                    start_timestamp=submission_start_ts,
                ),
                start=1,
            ):
                task_uuid = submission.get("task_uuid")
                task_link = tau_clients.get_task_link(task_uuid, prefer_load_balancer=True)
                print(f"File '{task_to_source[task_uuid]}' finished analysis: {task_link}")
                print(f"\tRemaining {len(submissions)-idx}/{len(submissions)}...")
        except KeyboardInterrupt:
            print("Waiting for results interrupted by user")

    print("Done")
    return 0


if __name__ == "__main__":
    sys.exit(main())

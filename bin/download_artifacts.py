#!/usr/bin/env python3
# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import argparse
import collections
import configparser
import datetime
import itertools
import os
import sys

import tau_clients
from tau_clients import decoders
from tau_clients import exceptions
from tau_clients import nsx_defender


UTC_NOW = datetime.datetime.utcnow()

METADATA_TYPES = [
    tau_clients.METADATA_TYPE_PCAP,
    tau_clients.METADATA_TYPE_PROCESS_SNAPSHOT,
    tau_clients.METADATA_TYPE_YARA_STRINGS,
    tau_clients.METADATA_TYPE_CODEHASH,
    tau_clients.METADATA_TYPE_SCREENSHOT,
    tau_clients.METADATA_TYPE_SFC,
    tau_clients.METADATA_TYPE_FILE,
    tau_clients.METADATA_TYPE_EXECUTED_SCRIPT,
    tau_clients.METADATA_TYPE_REPORT,
    tau_clients.METADATA_TYPE_ANALYSIS_SUBJECT,
]


def is_valid_output_directory(dir_path: str) -> str:
    """
    Validate the path to a directory.

    :param str dir_path: the path
    :rtype: str
    :return: the validated dir path
    :raises ValueError: if the path is not valid
    """
    if not os.path.isdir(dir_path):
        raise ValueError(f"Invalid directory path '{dir_path}'")
    return dir_path


def main():
    """Get public artifacts from file hashes or task uuids."""
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
        "-o",
        "--output-directory",
        dest="output_directory",
        default="./",
        type=is_valid_output_directory,
        help="output directory, defaults to current directory",
    )
    parser.add_argument(
        "-t",
        "--artifact-types",
        dest="artifact_types",
        choices=METADATA_TYPES + ["all"],
        nargs="+",
        default=["all"],
        help="the artifact types, i.e., PCAPs, code hash files, etc.",
    )
    parser.add_argument(
        "-d",
        "--disable-sandbox-filter",
        dest="disable_sandbox_filter",
        action="store_true",
        default=False,
        help="whether to search metadata in all reports rather than only sandbox (slower)",
    )
    decoders.InputTypeDecoder.add_arguments_to_parser(
        parser=parser,
        choices=[
            decoders.InputType.TASK_UUID,
            decoders.InputType.FILE_HASH,
            decoders.InputType.FILE,
        ],
    )
    args = parser.parse_args()
    conf = configparser.ConfigParser()
    conf.read(args.config_file)

    # Load the analysis client
    analysis_client = nsx_defender.MultiAnalysisClient.from_conf(conf, "analysis")

    # Parse the input
    if "all" in args.artifact_types:
        artifact_types = METADATA_TYPES
    else:
        artifact_types = args.artifact_types
    report_types = [] if args.disable_sandbox_filter else [tau_clients.REPORT_TYPE_SANDBOX]

    # Decode input type
    file_inputs, input_type = decoders.InputTypeDecoder().decode(
        arguments=args.input_bits,
        input_type=decoders.InputType(args.input_type),
        inspect_content=True,
    )
    print(
        f"Downloading '{','.join(artifact_types)}' (from '{','.join(report_types) or 'all'}') "
        f"for {len(file_inputs)} inputs of type '{input_type}'"
    )

    # Get mapping from hash -> task uuids
    if input_type is decoders.InputType.TASK_UUID:
        hash_to_tasks = collections.defaultdict(set)
        for uuid in file_inputs:
            try:
                ret = analysis_client.get_task_metadata(uuid)
                hash_to_tasks[ret["file_sha256"]].add(uuid)
                print(f"Task {uuid} found")
            except exceptions.ApiError:
                print(f"Task {uuid} NOT found")
    elif input_type is decoders.InputType.FILE_HASH:
        hash_to_tasks = collections.defaultdict(set)
        for file_hash in file_inputs:
            ret = analysis_client.query_file_hash(file_hash)
            for task in ret.get("tasks", []):
                hash_to_tasks[file_hash].add(task["task_uuid"])
            if file_hash in hash_to_tasks:
                print(f"File {file_hash} found")
            else:
                print(f"File {file_hash} NOT found")
    else:
        raise ValueError("Unknown input type")
    print(
        f"Validated {len(hash_to_tasks)} file hashes "
        f"for {len(list(itertools.chain(*hash_to_tasks.values())))} task uuids"
    )

    # Get mapping from hash -> (task uuid, report uuid, artifact name, artifact type)
    hash_to_artifact_names = collections.defaultdict(list)
    for file_hash, task_uuids in hash_to_tasks.items():
        for task_uuid in task_uuids:
            results = analysis_client.get_result_artifact_names(
                uuid=task_uuid,
                report_types=report_types,
                metadata_types=artifact_types,
            )
            for artifact_type in artifact_types:
                nb_count = len([x for x in results if x["artifact_type"] == artifact_type])
                nb_count_expired = len(
                    [
                        x
                        for x in results
                        if (
                            x["artifact_type"] == artifact_type
                            and x["delete_date"]
                            and x["delete_date"] <= UTC_NOW
                        )
                    ]
                )
                print(
                    f"[{file_hash}][{task_uuid}] Found {nb_count} "
                    f"({nb_count_expired} expired) {artifact_type}(s)"
                )
            for result in results:
                if not result["delete_date"] or result["delete_date"] > UTC_NOW:
                    hash_to_artifact_names[file_hash].append(result)

    # Download all artifacts
    for file_hash, artifact_names in hash_to_artifact_names.items():
        for artifact_name in artifact_names:
            file_name = (
                f"{file_hash}.{artifact_name['task_uuid']}.{artifact_name['report_uuid']}."
                f"{artifact_name['artifact_name']}"
            )
            print(f"[{file_hash}] Downloading {artifact_name['artifact_type']} {file_name}")
            try:
                artifact_data = analysis_client.get_artifact(
                    uuid=artifact_name["task_uuid"],
                    report_uuid=artifact_name["report_uuid"],
                    artifact_name=artifact_name["artifact_name"],
                )
                with open(os.path.join(args.output_directory, file_name), "wb") as f:
                    f.write(artifact_data.read())
            except tau_clients.exceptions.ApiError as ae:
                print(f"\tError: {str(ae)}")

    print("Done")
    return 0


if __name__ == "__main__":
    sys.exit(main())

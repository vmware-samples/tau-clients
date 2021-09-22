#!/usr/bin/env python
# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import argparse
import collections
import configparser
import itertools
import os
import sys

import tau_clients
from tau_clients import exceptions
from tau_clients import nsx_defender


INPUT_TYPE_FILE_HASH = "file-hash"

INPUT_TYPE_TASK_UUID = "task-uuid"

METADATA_TYPES = [
    tau_clients.METADATA_TYPE_PCAP,
    tau_clients.METADATA_TYPE_PROCESS_SNAPSHOT,
    tau_clients.METADATA_TYPE_YARA_STRINGS,
    tau_clients.METADATA_TYPE_CODEHASH,
    tau_clients.METADATA_TYPE_SCREENSHOT,
    tau_clients.METADATA_TYPE_SFC,
]


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
        type=is_valid_config_file,
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
        "-u",
        "--input-type",
        dest="input_type",
        choices=[
            INPUT_TYPE_TASK_UUID,
            INPUT_TYPE_FILE_HASH,
        ],
        default=None,
        help="what the input represents, file hashes or task uuids (defaults to auto-detect)",
    )
    parser.add_argument(
        "-d",
        "--disable-sandbox-filter",
        dest="disable_sandbox_filter",
        action="store_true",
        default=False,
        help="whether to search metadata in all reports rather than only sandbox (slower)",
    )
    parser.add_argument(
        "file_inputs",
        metavar="file_inputs",
        nargs="+",
        help="file hashes or task uuids",
    )
    args = parser.parse_args()
    conf = configparser.ConfigParser()
    conf.read(args.config_file)

    # Load the analysis client
    analysis_client = nsx_defender.MultiAnalysisClient.from_conf(conf, "analysis")

    # Parse the input
    artifact_types = METADATA_TYPES if "all" in args.artifact_types else args.artifact_types
    report_types = [] if args.disable_sandbox_filter else [tau_clients.REPORT_TYPE_SANDBOX]

    # Decode input type
    input_type = args.input_type
    if not input_type:
        if all(tau_clients.is_likely_task_uuid(x) for x in args.file_inputs):
            print("Input will be treated as task uuids (use '-u' to force input type)")
            input_type = INPUT_TYPE_TASK_UUID
        elif all(not tau_clients.is_likely_task_uuid(x) for x in args.file_inputs):
            print("Input will be treated as file hashes (use '-u' to force input type)")
            input_type = INPUT_TYPE_FILE_HASH
        else:
            raise ValueError("Mixed input is not supported (use '-u' to force input type)")
    print(
        f"Downloading '{','.join(artifact_types)}' (from '{','.join(report_types) or 'all'}') "
        f"for {len(args.file_inputs)} inputs of type '{input_type}'"
    )

    # Get mapping from hash -> task uuids
    if input_type == INPUT_TYPE_TASK_UUID:
        hash_to_tasks = collections.defaultdict(set)
        for uuid in args.file_inputs:
            try:
                ret = analysis_client.get_task_metadata(uuid)
                hash_to_tasks[ret["file_sha256"]].add(uuid)
                print(f"Task {uuid} found")
            except exceptions.ApiError:
                print(f"Task {uuid} NOT found")
    else:
        hash_to_tasks = collections.defaultdict(set)
        for file_hash in args.file_inputs:
            ret = analysis_client.query_file_hash(file_hash)
            for task in ret.get("tasks", []):
                hash_to_tasks[file_hash].add(task["task_uuid"])
            if file_hash in hash_to_tasks:
                print(f"File {file_hash} found")
            else:
                print(f"File {file_hash} NOT found")
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
                print(f"[{file_hash}][{task_uuid}] Found {nb_count} {artifact_type}(s)")
            for result in results:
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

    return 0


if __name__ == "__main__":
    sys.exit(main())

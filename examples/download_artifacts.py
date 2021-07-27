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


DEFAULT_DATA_CENTER = tau_clients.NSX_DEFENDER_DC_WESTUS

INPUT_TYPE_FILE_HASH = "file-hash"

INPUT_TYPE_TASK_UUID = "task-uuid"


def main():
    """Get artifacts from file hashes or task uuids."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--config-file",
        dest="config_file",
        default="./data/tau_clients.ini",
        help="read config from here",
    )
    parser.add_argument(
        "-o",
        "--output-directory",
        dest="output_directory",
        default="./",
        help="output directory",
    )
    parser.add_argument(
        "-t",
        "--artifact-types",
        dest="artifact_types",
        choices=[
            tau_clients.METADATA_TYPE_PCAP,
            tau_clients.METADATA_TYPE_PROCESS_SNAPSHOT,
            tau_clients.METADATA_TYPE_YARA_STRINGS,
            tau_clients.METADATA_TYPE_CODEHASH,
            tau_clients.METADATA_TYPE_SCREENSHOT,
            tau_clients.METADATA_TYPE_SFC,
        ],
        nargs="+",
        required=True,
        help="the artifact types",
    )
    parser.add_argument(
        "-u",
        "--input-type",
        dest="input_type",
        choices=[
            INPUT_TYPE_TASK_UUID,
            INPUT_TYPE_FILE_HASH,
        ],
        default=INPUT_TYPE_FILE_HASH,
        help="what the input represents, whether file hashes or task uuids",
    )
    parser.add_argument(
        "-d",
        "--disable-sandbox-filter",
        dest="disable_sandbox_filter",
        action="store_true",
        default=False,
        help="whether to search metadata from all reports rather than only sandbox (slower)",
    )
    parser.add_argument(
        "file_inputs",
        metavar="file_inputs",
        nargs="+",
        help="the inputs, file hashes but can also be task uuids depending on other options",
    )
    args = parser.parse_args()
    conf = configparser.ConfigParser()
    conf.read(args.config_file)

    # Load the analysis client
    analysis_clients = nsx_defender.AnalysisClient.from_conf_all(conf, "analysis")
    print(f"Client for {','.join(analysis_clients)} data-centers loaded")

    # Parse the input
    report_types = [] if args.disable_sandbox_filter else [tau_clients.REPORT_TYPE_SANDBOX]
    artifact_types_str = ",".join(args.artifact_types)
    report_types_str = ",".join(report_types) or "all"

    # Get mapping from hash -> task uuids
    print(
        f"Downloading '{artifact_types_str}' (from '{report_types_str}') "
        f"for {len(args.file_inputs)} inputs of type '{args.input_type}'"
    )
    if args.input_type == INPUT_TYPE_TASK_UUID:
        hash_to_tasks = collections.defaultdict(set)
        for uuid in args.file_inputs:
            try:
                ret = analysis_clients[DEFAULT_DATA_CENTER].get_task_metadata(uuid)
                hash_to_tasks[ret["file_sha256"]].add(uuid)
                print(f"Task {uuid} found")
            except exceptions.ApiError:
                print(f"Task {uuid} NOT found")
    elif args.input_type == INPUT_TYPE_FILE_HASH:
        hash_to_tasks = collections.defaultdict(set)
        hash_to_datacenter = {}
        for file_hash in args.file_inputs:
            for data_center, analysis_client in analysis_clients.items():
                ret = analysis_client.query_file_hash(file_hash)
                for task in ret.get("tasks", []):
                    hash_to_tasks[file_hash].add(task["task_uuid"])
                    hash_to_datacenter[file_hash] = data_center
            if file_hash in hash_to_tasks:
                print(f"File {file_hash} found in {hash_to_datacenter[file_hash]}")
            else:
                print(f"File {file_hash} NOT found")
    else:
        raise ValueError(f"Invalid input type: {args.input_type}")
    print(
        f"Validated {len(hash_to_tasks)} file hashes "
        f"for {len(list(itertools.chain(*hash_to_tasks.values())))} task uuids"
    )

    # Get mapping from hash -> (task uuid, report uuid, artifact name, artifact type)
    hash_to_artifact_names = collections.defaultdict(list)
    for file_hash, task_uuids in hash_to_tasks.items():
        for task_uuid in task_uuids:
            results = analysis_clients[DEFAULT_DATA_CENTER].get_result_artifact_names(
                uuid=task_uuid,
                report_types=report_types,
                metadata_types=args.artifact_types,
            )
            for artifact_type in args.artifact_types:
                nb_count = len([x for x in results if x["artifact_type"] == artifact_type])
                print(f"[{file_hash}][{task_uuid}] Found {nb_count} {artifact_type}(s)")
            for result in results:
                hash_to_artifact_names[file_hash].append(result)

    # Download all artifacts
    for file_hash, artifact_names in hash_to_artifact_names.items():
        for artifact_name in artifact_names:
            file_name = "{file_hash}.{task_uuid}.{report_uuid}.{artifact_name}".format(
                file_hash=file_hash,
                task_uuid=artifact_name["task_uuid"],
                report_uuid=artifact_name["report_uuid"],
                artifact_name=artifact_name["artifact_name"],
            )
            print(f"[{file_hash}] Downloading {artifact_name['artifact_type']} {file_name}")
            artifact_data = analysis_clients[DEFAULT_DATA_CENTER].get_artifact(
                uuid=artifact_name["task_uuid"],
                report_uuid=artifact_name["report_uuid"],
                artifact_name=artifact_name["artifact_name"],
            )
            with open(os.path.join(args.output_directory, file_name), "wb") as f:
                f.write(artifact_data.read())

    return 0


if __name__ == "__main__":
    sys.exit(main())

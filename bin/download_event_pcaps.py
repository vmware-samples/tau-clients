#!/usr/bin/env python3
# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import argparse
import configparser
import os
import sys
from typing import Dict

import tau_clients
from tau_clients import nsx_defender


def get_event_descriptor(
    portal_clients: Dict[str, "nsx_defender.PortalClient"],
    portal_link: str,
) -> "tau_clients.EventDescriptor":
    """
    Get event descriptor from a portal link.

    :param dict[str, PortalClient] portal_clients: the clients
    :param str portal_link: portal link pointing to the network event
    :rtype: EventDescriptor
    :return: the event descriptor
    :raise ValueError: if it is not possible to parse the portal link
    """
    event_descriptor = tau_clients.parse_portal_link(portal_link)
    if not event_descriptor:
        raise ValueError(f"Could not parse link: {portal_link}")
    if not event_descriptor.event_time:
        event = portal_clients[event_descriptor.data_center].get_event(
            event_id=event_descriptor.event_id,
            obfuscated_key_id=event_descriptor.obfuscated_key_id,
            obfuscated_subkey_id=event_descriptor.obfuscated_subkey_id,
        )
        if not event:
            raise ValueError(f"Could not find event {event_descriptor.event_id}")
        event_descriptor = event_descriptor._replace(event_time=event["start_time"])
    return event_descriptor


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
    """Download PCAPs given an event URL."""
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
        dest="portal_url",
        help="the portal url",
    )

    # Parse options
    args = parser.parse_args()
    conf = configparser.ConfigParser()
    conf.read(args.config_file)

    # Init clients
    portal_clients = nsx_defender.PortalClient.from_conf_all(conf, "portal")

    # Get event descriptor containing all information about an event
    event_descriptor = get_event_descriptor(portal_clients, portal_link=args.portal_url)

    # Get PCAPs
    event_info = portal_clients[event_descriptor.data_center].get_event_info(
        event_id=event_descriptor.event_id,
        event_time=event_descriptor.event_time,
        obfuscated_key_id=event_descriptor.obfuscated_key_id,
        obfuscated_subkey_id=event_descriptor.obfuscated_subkey_id,
    )
    pcap_ids = {x["pcap_id"] for x in event_info if "pcap_id" in x}
    for pcap_id in pcap_ids:
        file_name = "{}.{}.pcap".format(event_descriptor.event_id, pcap_id)
        file_path = os.path.join(args.output_directory, file_name)
        if os.path.exists(file_path):
            print(f"Skipping PCAP {file_name}")
            continue

        pcap_data = portal_clients[event_descriptor.data_center].get_pcap(
            pcap_id=pcap_id,
            event_time=event_descriptor.event_time,
            obfuscated_key_id=event_descriptor.obfuscated_key_id,
            obfuscated_subkey_id=event_descriptor.obfuscated_subkey_id,
        )
        print(f"Persisting event PCAP {file_name}")
        with open(file_path, "wb") as f:
            f.write(pcap_data.read())

    return 0


if __name__ == "__main__":
    sys.exit(main())

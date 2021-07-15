#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Script to test Opensource clients.

:Copyright:
     Copyright 2021 VMware, Inc.  All Rights Reserved.
"""
import argparse
import configparser
import datetime
import sys

from tau_clients import exceptions
from tau_clients import nsx_ata


TEST_UUID = "dbc8b217c32a00102d2f5c684d666f47"

TEST_SHA1 = "ba81b98f00168b86578e5f5de93d26ed83769432"


def main():
    """Run script."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--config-file",
        dest="config_file",
        default="./data/tau_clients.ini",
        help="read config from here",
    )

    # Parse options
    args = parser.parse_args()
    conf = configparser.ConfigParser()
    conf.read(args.config_file)

    # Create a configuration with wrong passwords
    conf_wrong = configparser.ConfigParser()
    conf_wrong.read(args.config_file)
    conf_wrong.set("portal", "password", "wrong")
    conf_wrong.set("analysis", "api_token", "wrong")

    print("**** PORTAL ****")
    client = nsx_ata.PortalClient.client_from_config(conf, section_name="portal")
    result = client.get_tasks_from_knowledgebase(
        query_string="file_sha1: '{}'".format(TEST_SHA1), include_private=True, limit=2
    )
    print("API result", result)
    result = client.get_progress(TEST_UUID)
    print("API result", result)
    result = client.submit_url("http://www.google.com")
    print("API result", result)
    try:
        client = nsx_ata.PortalClient.client_from_config(
            conf_wrong, section_name="portal"
        )
        _ = client.get_progress(TEST_UUID)
    except exceptions.ApiError as ae:
        if ae.error_msg.startswith("Authentication Error"):
            print("Correctly raised authentication error")
        else:
            raise

    print("**** ANALYSIS ****")
    client = nsx_ata.AnalysisClient.client_from_config(conf, section_name="analysis")
    result = client.get_analysis_tags(TEST_UUID)
    print("API result", result)
    result = client.query_file_hash(TEST_SHA1)
    print("API result", result)
    result = client.get_progress(TEST_UUID)
    print("API result", result)
    result = client.get_completed(
        after=datetime.datetime.utcnow() - datetime.timedelta(hours=5)
    )
    print("API result", result)
    result = client.submit_url("http://www.google.com")
    print("API result", result)
    try:
        client = nsx_ata.AnalysisClient.client_from_config(
            conf_wrong, section_name="analysis"
        )
        _ = client.get_analysis_tags(TEST_UUID)
    except exceptions.ApiError as ae:
        if ae.error_msg.startswith("Invalid Credentials"):
            print("Correctly raised authentication error")
        else:
            raise

    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
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

UTC_NOW = datetime.datetime.utcnow()


def to_str(result, max_len=32):
    str_result = str(result)
    if len(str_result) > max_len:
        return "{} ... (print truncated)".format(str_result[:max_len])
    else:
        return str_result


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

    portal_client = nsx_ata.PortalClient.from_conf(conf, section_name="portal")
    result = portal_client.get_tasks_from_knowledgebase(
        query_string="file_sha1: '{}'".format(TEST_SHA1), include_private=True, limit=2
    )
    print("PORTAL API - get_tasks_from_knowledgebase", to_str(result))
    result = portal_client.get_progress(TEST_UUID)
    print("PORTAL API - get_progress", to_str(result))
    result = portal_client.submit_url("https://www.google.com")
    print("PORTAL API - submit_url", to_str(result))
    try:
        client = nsx_ata.PortalClient.from_conf(conf_wrong, section_name="portal")
        _ = client.get_progress(TEST_UUID)
    except exceptions.ApiError as ae:
        if ae.error_msg.startswith("Authentication Error"):
            print("PORTAL API - correctly raised authentication error")
        else:
            raise

    analysis_client = nsx_ata.AnalysisClient.from_conf(conf, section_name="analysis")
    result = analysis_client.get_analysis_tags(TEST_UUID)
    print("ANALYSIS API - get_analysis_tags", to_str(result))
    result = analysis_client.query_file_hash(TEST_SHA1)
    print("ANALYSIS API - query_file_hash", to_str(result))
    result = analysis_client.get_progress(TEST_UUID)
    print("ANALYSIS API - get_progress", to_str(result))
    result = analysis_client.get_completed(after=UTC_NOW - datetime.timedelta(hours=5))
    print("ANALYSIS API - get_completed", to_str(result))
    result = analysis_client.submit_url("https://www.google.com")
    print("ANALYSIS API - submit_url", to_str(result))
    try:
        client = nsx_ata.AnalysisClient.from_conf(conf_wrong, section_name="analysis")
        _ = client.get_analysis_tags(TEST_UUID)
    except exceptions.ApiError as ae:
        if ae.error_msg.startswith("Invalid Credentials"):
            print("ANALYSIS API - correctly raised authentication error")
        else:
            raise

    res1 = portal_client.get_result(TEST_UUID)
    res2 = analysis_client.get_result(TEST_UUID)
    print("COMPARISON - get_result", str(res1)[:128] == str(res2)[:128])

    return 0


if __name__ == "__main__":
    sys.exit(main())

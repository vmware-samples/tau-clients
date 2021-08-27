#!/usr/bin/env python
# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import json
import unittest

import ddt
import mock
from tau_clients import parsers

REPORT1_LOCATION = "./data/report1.txt"
REPORT2_LOCATION = "./data/report2.txt"
ANALYSIS_LINK1 = (
    "https://user.lastline.com/portal#/analyst/task/f5aba6c1573600100eb9536af678ff2f/overview"
)
ANALYSIS_LINK2 = (
    "https://user.lastline.com/portal#/analyst/task/dd3887255af0001029a38ffcb0d840a4/overview"
)
EXPECTED_ATTRIBUTE = {
    "Attribute": mock.ANY,
    "description": mock.ANY,
    "distribution": mock.ANY,
    "meta-category": mock.ANY,
    "name": mock.ANY,
    "sharing_group_id": mock.ANY,
    "template_uuid": mock.ANY,
    "template_version": mock.ANY,
    "uuid": mock.ANY,
}
EXPECTED_RESULT = {
    "Object": [
        EXPECTED_ATTRIBUTE,
        EXPECTED_ATTRIBUTE,
        EXPECTED_ATTRIBUTE,
    ],
    "uuid": mock.ANY,
}


@ddt.ddt
class ClientTestCase(unittest.TestCase):
    """Test some basic utilities."""

    with open(REPORT1_LOCATION) as json_file:
        report1 = json.load(json_file)
    with open(REPORT2_LOCATION) as json_file:
        report2 = json.load(json_file)

    @ddt.data(
        (report1, ANALYSIS_LINK1, EXPECTED_RESULT),
        (report2, ANALYSIS_LINK2, EXPECTED_RESULT),
    )
    def test_(self, args):
        """Test ResultParser."""
        report, analysis_link, expected_misp_event = args
        result_parser = parsers.ResultParser()
        misp_event = result_parser.parse(analysis_link, report)
        result = json.loads(misp_event.to_json())
        self.assertEqual(result, expected_misp_event)


if __name__ == "__main__":
    unittest.main()

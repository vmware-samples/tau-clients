#!/usr/bin/env python
# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import importlib
import json
import unittest

import ddt
import mock

try:
    parsers = importlib.import_module("tau_clients.parsers")
except ImportError:
    parsers = None


TECHNIQUES_GALAXY = "./data/techniques_galaxy.json"


EXPECTED_OBJECT_1_1 = {
    "Attribute": [
        {
            "uuid": mock.ANY,
            "object_relation": mock.ANY,
            "value": "723cd30b9a09f9954962a96a6c1c2826",
            "type": "md5",
            "disable_correlation": mock.ANY,
            "to_ids": mock.ANY,
            "category": mock.ANY,
        },
        {
            "uuid": mock.ANY,
            "object_relation": mock.ANY,
            "value": "efc6c117ecc6253ed7400c53b2e148d5e4068636",
            "type": "sha1",
            "disable_correlation": mock.ANY,
            "to_ids": mock.ANY,
            "category": mock.ANY,
        },
        {
            "uuid": mock.ANY,
            "object_relation": mock.ANY,
            "value": "528a43b50ff7e8fbce81691c409e6223ee564506b98d17814e510ee9278a6f53",
            "type": "sha256",
            "disable_correlation": mock.ANY,
            "to_ids": mock.ANY,
            "category": mock.ANY,
        },
        {
            "uuid": mock.ANY,
            "object_relation": mock.ANY,
            "value": "application/x-pe-dll-32bit-i386",
            "type": "mime-type",
            "disable_correlation": mock.ANY,
            "to_ids": mock.ANY,
            "category": mock.ANY,
        },
    ],
    "description": mock.ANY,
    "distribution": mock.ANY,
    "meta-category": mock.ANY,
    "name": "file",
    "sharing_group_id": mock.ANY,
    "template_uuid": mock.ANY,
    "template_version": mock.ANY,
    "uuid": mock.ANY,
}

EXPECTED_OBJECT_1_2 = {
    "Attribute": [
        {
            "uuid": mock.ANY,
            "object_relation": mock.ANY,
            "value": "100",
            "type": "text",
            "disable_correlation": mock.ANY,
            "to_ids": mock.ANY,
            "category": mock.ANY,
        },
        {
            "uuid": mock.ANY,
            "object_relation": mock.ANY,
            "value": "saas",
            "type": "text",
            "disable_correlation": mock.ANY,
            "to_ids": mock.ANY,
            "category": mock.ANY,
        },
        {
            "uuid": mock.ANY,
            "object_relation": mock.ANY,
            "value": "vmware-nsx-defender",
            "type": "text",
            "disable_correlation": mock.ANY,
            "to_ids": mock.ANY,
            "category": mock.ANY,
        },
        {
            "uuid": mock.ANY,
            "object_relation": mock.ANY,
            "value": mock.ANY,
            "type": "link",
            "disable_correlation": mock.ANY,
            "to_ids": mock.ANY,
            "category": "External analysis",
        },
    ],
    "description": mock.ANY,
    "distribution": mock.ANY,
    "meta-category": mock.ANY,
    "name": "sandbox-report",
    "sharing_group_id": mock.ANY,
    "template_uuid": mock.ANY,
    "template_version": mock.ANY,
    "uuid": mock.ANY,
}

EXPECTED_OBJECT_1_3 = {
    "Attribute": [
        {
            "uuid": mock.ANY,
            "object_relation": "software",
            "value": "VMware NSX Defender",
            "type": "text",
            "disable_correlation": mock.ANY,
            "to_ids": mock.ANY,
            "category": mock.ANY,
        },
        {
            "uuid": mock.ANY,
            "object_relation": "signature",
            "value": "Anomaly: AI detected possible malicious code reuse",
            "type": "text",
            "disable_correlation": mock.ANY,
            "to_ids": mock.ANY,
            "category": mock.ANY,
        },
        {
            "uuid": mock.ANY,
            "object_relation": "signature",
            "value": "Evasion: Ability to check the disk size",
            "type": "text",
            "disable_correlation": mock.ANY,
            "to_ids": mock.ANY,
            "category": mock.ANY,
        },
        {
            "uuid": mock.ANY,
            "object_relation": "signature",
            "value": "Family: Ability to request high privileges",
            "type": "text",
            "disable_correlation": mock.ANY,
            "to_ids": mock.ANY,
            "category": mock.ANY,
        },
        {
            "uuid": mock.ANY,
            "object_relation": "signature",
            "value": "Network: Ability to establish connection with server using Windows socket",
            "type": "text",
            "disable_correlation": mock.ANY,
            "to_ids": mock.ANY,
            "category": mock.ANY,
        },
        {
            "uuid": mock.ANY,
            "object_relation": "signature",
            "value": "Search: Retrieving the user account name",
            "type": "text",
            "disable_correlation": mock.ANY,
            "to_ids": mock.ANY,
            "category": mock.ANY,
        },
        {
            "uuid": mock.ANY,
            "object_relation": "signature",
            "value": "Signature: Identified trojan code",
            "type": "text",
            "disable_correlation": mock.ANY,
            "to_ids": mock.ANY,
            "category": mock.ANY,
        },
    ],
    "description": mock.ANY,
    "distribution": mock.ANY,
    "meta-category": mock.ANY,
    "name": "sb-signature",
    "sharing_group_id": mock.ANY,
    "template_uuid": mock.ANY,
    "template_version": mock.ANY,
    "uuid": mock.ANY,
}

EXPECTED_RESULT_1 = {
    "Object": [
        EXPECTED_OBJECT_1_1,
        EXPECTED_OBJECT_1_2,
        EXPECTED_OBJECT_1_3,
    ],
    "uuid": mock.ANY,
}


@ddt.ddt
@unittest.skipUnless(parsers, "Module 'parsers' is not available")
class ParsersTestCase(unittest.TestCase):
    """Test the report parser."""

    @ddt.data("", None, "address.in-addr.arpa", "8.8.8.8")
    def test_hostname_validation__error(self, args):
        """Test validation when failing."""
        hostname = args
        with self.assertRaises(ValueError):
            _ = parsers.ResultParserMISP.validate_hostname(hostname)

    @ddt.data(
        ("www.google.com", "www.google.com"),
        ("www.google.com.", "www.google.com"),
    )
    def test_hostname_validation(self, args):
        """Test validation when passing."""
        hostname_input, hostname_output = args
        ret = parsers.ResultParserMISP.validate_hostname(hostname_input)
        self.assertEqual(ret, hostname_output)

    @ddt.data(
        (
            "./data/f5aba6c1573600100eb9536af678ff2f.json",
            "https://user.lastline.com/portal#/analyst/task/"
            "f5aba6c1573600100eb9536af678ff2f/overview",
            EXPECTED_RESULT_1,
        ),
    )
    def test_result_parser_misp(self, args):
        """Test ResultParserMISP."""
        report_file, analysis_link, expected_misp_event_json = args
        with open(report_file, "r") as json_file:
            report_data = json.load(json_file)
        misp_event = parsers.ResultParserMISP().parse(analysis_link, report_data)
        misp_event_json = json.loads(misp_event.to_json())
        self.assertEqual(misp_event_json, expected_misp_event_json)

    @ddt.data(
        (
            {
                "Search: Retrieving the user account name": [
                    {
                        "tactics": [{"id": "TA0007", "name": "Discovery"}],
                        "id": "T1033",
                        "name": "System Owner/User Discovery",
                    }
                ]
            },
            [{"name": 'misp-galaxy:mitre-attack-pattern="System Owner/User Discovery - T1033"'}],
        )
    )
    def test_result_parser_galaxy(self, args):
        """Test the parsing of activities."""
        activities, tags = args
        report_data = {
            "analysis_subject": {
                "md5": "a" * 32,
                "sha1": "b" * 40,
                "sha256": "c" * 64,
                "mime_type": "unknown",
            },
            "activity_to_mitre_techniques": activities,
            "score": 70,
        }
        with open(TECHNIQUES_GALAXY, "r") as galaxy_file:
            galaxy_data = json.load(galaxy_file)
        misp_event = parsers.ResultParserMISP(galaxy_data).parse("<garbage>", report_data)
        misp_event_json = json.loads(misp_event.to_json())
        self.assertCountEqual(misp_event_json["Tag"], tags)


if __name__ == "__main__":
    unittest.main()

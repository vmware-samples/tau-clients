#!/usr/bin/env python
# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
import configparser
import datetime
import gc
import io
import unittest

import mock
from nose.plugins.attrib import attr
from tau_clients import exceptions
from tau_clients import nsx_defender


TEST_UUID = "dbc8b217c32a00102d2f5c684d666f47"

TEST_SHA1 = "ba81b98f00168b86578e5f5de93d26ed83769432"

TEST_SHA256 = "e230f33416157afbb22c6db78c7a4aec057e45a709ce3a36d8dc77291d70dd45"

TEST_ARTIFACT_UUID = "aba8dccf1641001000c9dd8526ac7c9d"

TEST_ARTIFACT_REPORT_UUID = "4ffa644851ebe118wu1pbwlt3C44cwAYRtfdXY5L3gRhHJ_QANAyuQ"

TEST_ARTIFACT_NAME = "process_snapshots_1"

TEST_URL = "https://www.google.com"

UTC_NOW = datetime.datetime.utcnow()

CONF_LOCATION = "./data/tau_clients.ini"


@attr("live")
class TestLiveNSXDefenderClients(unittest.TestCase):
    """
    Run NSX Defender clients live:
        1) Copy './data/tau_clients.ini.template' to './data/tau_clients.ini'
        2) Fill './data/tau_clients.ini' with valid authentication data
        3) Run this test file: 'nosetests -a live tests/test_live_clients.py'
    """

    @classmethod
    def setUpClass(cls) -> None:
        """Load some common data structures."""
        cls.conf = configparser.ConfigParser()
        cls.conf.read(CONF_LOCATION)
        cls.conf_with_errors = configparser.ConfigParser()
        cls.conf_with_errors.read(CONF_LOCATION)
        cls.conf_with_errors.set("portal", "password", "wrong")
        cls.conf_with_errors.set("analysis", "api_token", "wrong")

    def test_analysis_client(self):
        """Test the analysis client."""
        analysis_client = nsx_defender.AnalysisClient.from_conf(self.conf, "analysis")
        result = analysis_client.get_analysis_tags(TEST_UUID)
        self.assertEqual(result, {"task_uuid": TEST_UUID, "analysis_tags": mock.ANY})
        result = analysis_client.get_progress(TEST_UUID)
        self.assertEqual(result, {"progress": 100, "completed": 1})
        result = analysis_client.query_file_hash(TEST_SHA1)
        self.assertEqual(result, {"tasks": mock.ANY, "files_found": mock.ANY})
        result = analysis_client.submit_url(TEST_URL)
        self.assertLessEqual({"task_uuid": mock.ANY}.items(), result.items())
        result = analysis_client.get_completed(after=UTC_NOW - datetime.timedelta(hours=5))
        self.assertEqual(
            result,
            {
                "tasks": mock.ANY,
                "after": mock.ANY,
                "more_results_available": mock.ANY,
                "resume": mock.ANY,
                "before": mock.ANY,
            },
        )

    def test_analysis_client__get_process_snapshot_names(self):
        """Test getting the process snapshot names."""
        analysis_client = nsx_defender.AnalysisClient.from_conf(self.conf, "analysis")
        result = analysis_client.get_result_artifact_names(TEST_ARTIFACT_UUID)
        self.assertIn(
            {
                "task_uuid": mock.ANY,
                "report_uuid": mock.ANY,
                "artifact_name": mock.ANY,
                "artifact_type": mock.ANY,
            },
            result,
        )

    def test_analysis_client__get_artifact(self):
        """
        Test getting a process snapshot.

        Note: this might start failing at some point due to data retention
        """
        analysis_client = nsx_defender.AnalysisClient.from_conf(self.conf, "analysis")
        result = analysis_client.get_result_artifact(
            uuid=TEST_ARTIFACT_UUID,
            report_uuid=TEST_ARTIFACT_REPORT_UUID,
            artifact_name=TEST_ARTIFACT_NAME,
        )
        self.assertIsInstance(result, io.BytesIO)
        self.assertGreater(len(result.read()), 100)

    def test_analysis_client__auth_error(self):
        """Test loading the analysis client with wrong credentials."""
        with self.assertRaisesRegexp(exceptions.ApiError, "Invalid Credentials"):
            client = nsx_defender.AnalysisClient.from_conf(self.conf_with_errors, "analysis")
            _ = client.get_analysis_tags(TEST_UUID)

    def test_portal_client(self):
        """Test the portal client."""
        portal_client = nsx_defender.PortalClient.from_conf(self.conf, "portal")
        result = portal_client.get_tasks_from_knowledgebase(
            query_string="file_sha1: '{}'".format(TEST_SHA1),
            include_private=True,
            limit=2,
        )
        self.assertIn(
            {
                "av_label": mock.ANY,
                "severity": mock.ANY,
                "submission": mock.ANY,
                "report_uuid": mock.ANY,
                "file_type": mock.ANY,
                "analysis_env": mock.ANY,
                "visibility": mock.ANY,
                "file_mime": mock.ANY,
                "task_uuid": mock.ANY,
                "score": mock.ANY,
                "artifact": mock.ANY,
                "artifact_type": mock.ANY,
                "backend_uuid": mock.ANY,
            },
            result,
        )
        result = portal_client.get_progress(TEST_UUID)
        self.assertEqual(result, {"progress": 100, "completed": 1})
        result = portal_client.submit_url(TEST_URL)
        self.assertLessEqual({"task_uuid": mock.ANY}.items(), result.items())

    def test_portal_client__auth_error(self):
        """Test loading the portal client with wrong credentials."""
        with self.assertRaisesRegexp(exceptions.ApiError, "Authentication Error"):
            client = nsx_defender.PortalClient.from_conf(self.conf_with_errors, "portal")
            _ = client.get_progress(TEST_UUID)

    def test_get_result_equivalence(self):
        """Test that both portal client and analysis return the same results."""
        portal_client = nsx_defender.PortalClient.from_conf(self.conf, "portal")
        analysis_client = nsx_defender.AnalysisClient.from_conf(self.conf, "analysis")
        res1 = portal_client.get_result(TEST_UUID)
        res2 = analysis_client.get_result(TEST_UUID)
        self.assertEqual(res1["reports"], res2["reports"])

    def test_multi_data_center_analysis_client(self):
        """Test the multi"""
        # Loading the multi-client "correctly"
        analysis_client1 = nsx_defender.MultiAnalysisClient.from_conf(
            conf=self.conf,
            section_name="analysis",
        )
        ret = analysis_client1.query_file_hash(TEST_SHA256)
        self.assertEqual(ret["files_found"], 1)
        del analysis_client1
        self.assertEqual(gc.collect(), 0)

        # Loading the multi-client "correctly" but removing the additional clients
        analysis_client2 = nsx_defender.MultiAnalysisClient.from_conf(self.conf, "analysis")
        analysis_client2.available_clients = {}
        ret = analysis_client2.query_file_hash(TEST_SHA256)
        self.assertEqual(ret["files_found"], 0)

        # Loading the multi-client "incorrectly"
        analysis_client3 = nsx_defender.MultiAnalysisClient(
            api_url=self.conf.get("analysis", "url").strip("/"),
            login_params=nsx_defender.MultiAnalysisClient._get_login_params(
                self.conf, "analysis"
            ),
            timeout=self.conf.getint("analysis", "timeout", fallback=60),
            verify_ssl=self.conf.getboolean("analysis", "verify_ssl", fallback=True),
        )
        ret = analysis_client3.query_file_hash(TEST_SHA256)
        self.assertEqual(ret["files_found"], 0)


if __name__ == "__main__":
    unittest.main()

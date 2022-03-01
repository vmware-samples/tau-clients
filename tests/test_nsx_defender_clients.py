#!/usr/bin/env python
# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import configparser
import json
import unittest
from typing import Any
from typing import Dict
from typing import Optional
from unittest.mock import call

import ddt
import mock
import requests.exceptions
import tau_clients
from tau_clients import exceptions
from tau_clients import nsx_defender


PORTAL_AUTH_DATA = {"username": "asd", "password": "dsa"}

ANALYSIS_AUTH_DATA = {"key": "asd", "api_token": "dsa"}

TEST_UUID = "a" * 32

TEST_API_URL = "https://<base>"

GATEWAY_TIMEOUT = b"""<html>
<head><title>504 Gateway Time-out</title></head>
<body bgcolor="white">
<center><h1>504 Gateway Time-out</h1></center>
<hr><center>nginx</center>
</body>
</html>
"""


def mock_response(
    status_code: int,
    content: Optional[Any] = None,
    headers: Optional[Dict] = None,
    reason: str = None,
    raw: bool = False,
) -> requests.Response:
    """
    Mock response.

    :param int status_code: the HTTP response code
    :param Any|None content: the option content
    :param Any|Dict headers: the headers
    :param str|None reason: the reason of the error
    :param bool raw: whether it is raw content
    :rtype: requests.Response
    :return: the mocked response
    """
    res = requests.Response()
    res.status_code = status_code
    res.url = TEST_API_URL
    res.reason = reason or "code"
    res.headers = headers or {}
    if content:
        if raw:
            res._content = content
        else:
            res._content = json.dumps(content).encode("utf-8")
    return res


@ddt.ddt
class AbstractClientTestCase(unittest.TestCase):
    """Test some utilities."""

    @ddt.data(
        (("login", []), "{}/login.json".format(TEST_API_URL)),
        (("login", []), "{}/login.json".format(TEST_API_URL)),
        (("analysis", ["test"]), "{}/analysis/test.json".format(TEST_API_URL)),
        (("analysis", ["test"], None), "{}/analysis/test".format(TEST_API_URL)),
        (
            ("knowledgebase", ["test"], "json"),
            "{}/knowledgebase/test.json".format(TEST_API_URL),
        ),
        (
            ("knowledgebase", ["test", "test2"], "json"),
            "{}/knowledgebase/test/test2.json".format(TEST_API_URL),
        ),
    )
    def test_build_url(self, args):
        """Test the method 'build_url'."""
        arguments, expected = args
        client = nsx_defender.PortalClient(api_url=TEST_API_URL, login_params=ANALYSIS_AUTH_DATA)
        self.assertEqual(client._build_url(*arguments), expected)


class PortalClientTestCase(unittest.TestCase):
    """Test the portal client."""

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_open_client__request_exception(self, requests_mock, session_mock):
        """Test the portal client when there is a timeout."""
        exception_message = "timeout"
        session_mock.request.side_effect = [requests.ReadTimeout(exception_message)]
        requests_mock.session.return_value = session_mock

        # Test the code
        client = nsx_defender.PortalClient(api_url=TEST_API_URL, login_params=PORTAL_AUTH_DATA)
        with self.assertRaisesRegexp(exceptions.CommunicationError, exception_message):
            _ = client.get_progress(TEST_UUID)

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_open_client__http_error(self, requests_mock, session_mock):
        """Test the portal client when there is a HTTP error."""
        exception_msg_regex = (
            r"No success field in response \(500 Server "
            r"Error: code for url: {}\)".format(TEST_API_URL)
        )
        session_mock.request.side_effect = [mock_response(500, "generic error")]
        requests_mock.session.return_value = session_mock

        # Test the code
        client = nsx_defender.PortalClient(api_url=TEST_API_URL, login_params=PORTAL_AUTH_DATA)
        with self.assertRaisesRegexp(exceptions.ApiError, exception_msg_regex):
            _ = client.get_progress(TEST_UUID)

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_open_client__http_error_gateway_timeout(self, requests_mock, session_mock):
        """Test the portal client when there is a HTTP error."""
        exception_msg_regex = (
            r"Response not json.*504 Server Error: Gateway Timeout.*"
            r"for url: {}\)".format(TEST_API_URL)
        )
        session_mock.request.side_effect = [
            mock_response(504, GATEWAY_TIMEOUT, raw=True, reason="Gateway Timeout")
        ]
        requests_mock.session.return_value = session_mock

        # Test the code
        client = nsx_defender.PortalClient(api_url=TEST_API_URL, login_params=PORTAL_AUTH_DATA)
        with self.assertRaisesRegexp(exceptions.ApiError, exception_msg_regex):
            _ = client.get_progress(TEST_UUID)

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_open_client__api_http_error(self, requests_mock, session_mock):
        """Test the portal client when there is a HTTP error and some API error data."""
        exception_msg_regex = (
            r"API Error \(3000\) \(500 Server " r"Error: code for url: {}\)".format(TEST_API_URL)
        )
        session_mock.request.side_effect = [
            mock_response(500, {"success": 0, "error_code": 3000, "error": "API Error"})
        ]
        requests_mock.session.return_value = session_mock

        # Test the code
        client = nsx_defender.PortalClient(api_url=TEST_API_URL, login_params=PORTAL_AUTH_DATA)
        with self.assertRaisesRegexp(exceptions.ApiError, exception_msg_regex):
            _ = client.get_progress(TEST_UUID)

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_open_client__api_error(self, requests_mock, session_mock):
        """Test the portal client when there is an authentication error."""
        exception_msg_regex = r"Authentication Error \(3004\)"
        session_mock.request.side_effect = [
            mock_response(
                200, {"success": 0, "error_code": 3004, "error": "Authentication Error"}
            )
        ]
        requests_mock.session.return_value = session_mock

        # Test the code
        client = nsx_defender.PortalClient(api_url=TEST_API_URL, login_params=PORTAL_AUTH_DATA)
        with self.assertRaisesRegexp(exceptions.ApiError, exception_msg_regex):
            _ = client.get_progress(TEST_UUID)

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_open_client(self, requests_mock, session_mock):
        """Test the portal client."""
        expected_result = {"progress": 100, "completed": 1}
        session_mock.request.side_effect = [
            mock_response(200, {"success": "1", "data": "true"}),
            mock_response(200, {"success": "1", "data": expected_result}),
        ]
        requests_mock.session.return_value = session_mock

        # Test the code
        client = nsx_defender.PortalClient(api_url=TEST_API_URL, login_params=PORTAL_AUTH_DATA)
        ret = client.get_progress(TEST_UUID)

        # Verify the asserts
        session_mock.request.assert_has_calls(
            [
                call(
                    params=None,
                    files=None,
                    headers=None,
                    method="POST",
                    data=PORTAL_AUTH_DATA,
                    stream=False,
                    timeout=mock.ANY,
                    url="{}/login.json".format(TEST_API_URL),
                    verify=True,
                ),
                call(
                    data=None,
                    files=None,
                    headers=None,
                    method="GET",
                    params={"uuid": TEST_UUID},
                    stream=False,
                    timeout=mock.ANY,
                    url="{}/analysis/get_progress.json".format(TEST_API_URL),
                    verify=True,
                ),
            ]
        )
        self.assertEqual(ret, expected_result)


class AnalysisClientTestCase(unittest.TestCase):
    """Test the analysis client."""

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_analysis_client__request_exception(self, requests_mock, session_mock):
        """Test the analysis client when there is a timeout."""
        exception_message = "timeout"
        session_mock.request.side_effect = [requests.ReadTimeout(exception_message)]
        requests_mock.session.return_value = session_mock

        # Test the code
        client = nsx_defender.AnalysisClient(
            api_url=TEST_API_URL, login_params=ANALYSIS_AUTH_DATA
        )
        with self.assertRaisesRegexp(exceptions.CommunicationError, exception_message):
            _ = client.get_analysis_tags(TEST_UUID)

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_analysis_client(self, requests_mock, session_mock):
        """Test the analysis client."""
        expected_result = {"progress": 100, "completed": 1}
        session_mock.request.side_effect = [
            mock_response(200, {"success": "1", "data": "true"}),
            mock_response(200, {"success": "1", "data": expected_result}),
        ]
        requests_mock.session.return_value = session_mock

        # Test the code
        client = nsx_defender.AnalysisClient(
            api_url=TEST_API_URL, login_params=ANALYSIS_AUTH_DATA
        )
        ret = client.get_progress(TEST_UUID)

        # Verify the asserts
        session_mock.request.assert_has_calls(
            [
                call(
                    data=ANALYSIS_AUTH_DATA,
                    params=None,
                    files=None,
                    headers=None,
                    method="POST",
                    stream=False,
                    timeout=mock.ANY,
                    url="{}/authentication/login.json".format(TEST_API_URL),
                    verify=True,
                ),
                call(
                    data=None,
                    params={"uuid": TEST_UUID},
                    files=None,
                    headers=None,
                    method="GET",
                    stream=False,
                    timeout=mock.ANY,
                    url="{}/analysis/get_progress.json".format(TEST_API_URL),
                    verify=True,
                ),
            ]
        )
        self.assertEqual(ret, expected_result)

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_analysis_client__get_process_snapshot_names(self, requests_mock, session_mock):
        """Test the analysis client when getting process snapshot names."""
        expected_result = [
            {
                "task_uuid": TEST_UUID,
                "report_uuid": "REPORT_UUID",
                "artifact_name": "NAME",
                "artifact_type": tau_clients.METADATA_TYPE_PCAP,
                "delete_date": None,
            }
        ]
        expected_result_1 = {
            "report": {},
            "reports": [{"report_version": "<data>", "report_uuid": "REPORT_UUID"}],
        }
        expected_result_2 = {
            "report": {
                "analysis_metadata": [
                    {"name": "NAME", "metadata_type": tau_clients.METADATA_TYPE_PCAP}
                ]
            },
            "reports": [{"report_version": "<data>", "report_uuid": "REPORT_UUID"}],
        }
        session_mock.request.side_effect = [
            mock_response(200, {"success": "1", "data": "true"}),
            mock_response(200, {"success": "1", "data": expected_result_1}),
            mock_response(200, {"success": "1", "data": expected_result_2}),
        ]
        requests_mock.session.return_value = session_mock

        # Test the code
        client = nsx_defender.AnalysisClient(
            api_url=TEST_API_URL, login_params=ANALYSIS_AUTH_DATA
        )
        ret = client.get_result_artifact_names(TEST_UUID)

        # Verify the asserts
        session_mock.request.assert_has_calls(
            [
                call(
                    data=ANALYSIS_AUTH_DATA,
                    params=None,
                    files=None,
                    headers=None,
                    method="POST",
                    stream=False,
                    timeout=mock.ANY,
                    url="{}/authentication/login.json".format(TEST_API_URL),
                    verify=True,
                ),
                call(
                    data=None,
                    params={"uuid": TEST_UUID, "full_report_score": -1},
                    files=None,
                    headers=None,
                    method="GET",
                    stream=False,
                    timeout=mock.ANY,
                    url="{}/analysis/get.json".format(TEST_API_URL),
                    verify=True,
                ),
                call(
                    data=None,
                    params={
                        "uuid": TEST_UUID,
                        "report_uuid": "REPORT_UUID",
                        "full_report_score": 0,
                    },
                    files=None,
                    headers=None,
                    method="GET",
                    stream=False,
                    timeout=mock.ANY,
                    url="{}/analysis/get.json".format(TEST_API_URL),
                    verify=True,
                ),
            ]
        )
        self.assertEqual(ret, expected_result)

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_analysis_client__get_artifact(self, requests_mock, session_mock):
        """Test the analysis client when getting an artifact."""
        expected_data = b"datadata"
        file_name = "file_name.bin"
        expected_file_name = "d0b54a6b712cc633e4f9ca3ede91807eb23eaef271e165e4c245c4bf83c3385d"
        session_mock.request.side_effect = [
            mock_response(200, {"success": "1", "data": "true"}),
            mock_response(
                200,
                expected_data,
                {"content-disposition": "attachment; filename={}".format(file_name)},
                raw=True,
            ),
        ]
        requests_mock.session.return_value = session_mock

        # Test the code
        client = nsx_defender.AnalysisClient(
            api_url=TEST_API_URL, login_params=ANALYSIS_AUTH_DATA
        )
        ret = client.get_artifact(TEST_UUID, "REPORT_UUID", "NAME")

        # Verify the asserts
        session_mock.request.assert_has_calls(
            [
                call(
                    data=ANALYSIS_AUTH_DATA,
                    params=None,
                    files=None,
                    headers=None,
                    method="POST",
                    stream=False,
                    timeout=mock.ANY,
                    url="{}/authentication/login.json".format(TEST_API_URL),
                    verify=True,
                ),
                call(
                    data=None,
                    params={
                        "uuid": TEST_UUID,
                        "report_uuid": "REPORT_UUID",
                        "artifact_name": "NAME",
                    },
                    files=None,
                    headers=None,
                    method="GET",
                    stream=False,
                    timeout=mock.ANY,
                    url="{}/analysis/get_report_artifact".format(TEST_API_URL),
                    verify=True,
                ),
            ]
        )
        self.assertEqual(ret.read(), expected_data)
        self.assertEqual(ret.name, expected_file_name)

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_analysis_client__get_artifact__api_error(self, requests_mock, session_mock):
        """Test the analysis client when getting an artifact and erroring out."""
        session_mock.request.side_effect = [
            mock_response(200, {"success": "1", "data": "true"}),
            mock_response(403, "asd"),
        ]
        requests_mock.session.return_value = session_mock

        # Test the code
        client = nsx_defender.AnalysisClient(
            api_url=TEST_API_URL, login_params=ANALYSIS_AUTH_DATA
        )
        with self.assertRaisesRegexp(exceptions.ApiError, "403 Client Error"):
            _ = client.get_artifact(TEST_UUID, "REPORT_UUID", "NAME")


class MultiDataCenterAnalysisClientTestCase(unittest.TestCase):
    """Test the multi analysis client."""

    def setUp(self) -> None:
        super(MultiDataCenterAnalysisClientTestCase, self).setUp()
        self.conf = configparser.ConfigParser()
        self.conf.add_section("analysis")
        self.conf.set("analysis", "api_token", ANALYSIS_AUTH_DATA["api_token"])
        self.conf.set("analysis", "key", ANALYSIS_AUTH_DATA["key"])

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_multi_analysis_client__multi_dispatch(self, requests_mock, session_mock):
        """Test the multi analysis client with multi dispatch."""
        expected_result = {"progress": 200, "completed": 2}
        result = {"progress": 100, "completed": 1}
        session_mock.request.side_effect = [
            mock_response(200, {"success": 1, "data": "true"}),
            mock_response(200, {"success": 1, "data": result}),
            mock_response(200, {"success": 1, "data": "true"}),
            mock_response(200, {"success": 1, "data": result}),
        ]
        requests_mock.session.return_value = session_mock
        # Test the code
        client = nsx_defender.MultiAnalysisClient.from_conf(self.conf, "analysis")
        ret = client.query_file_hash("a" * 32)
        # Verify the asserts
        session_mock.request.assert_has_calls(
            [
                call(
                    data=ANALYSIS_AUTH_DATA,
                    params=None,
                    files=None,
                    headers=None,
                    method="POST",
                    stream=False,
                    timeout=mock.ANY,
                    url="{}/authentication/login.json".format(
                        tau_clients.NSX_DEFENDER_ANALYSIS_URLS[tau_clients.NSX_DEFENDER_DC_WESTUS]
                    ),
                    verify=True,
                ),
                call(
                    data=None,
                    params={"hash_value": "a" * 32, "hash_algorithm": "md5"},
                    files=None,
                    headers=None,
                    method="GET",
                    stream=False,
                    timeout=mock.ANY,
                    url="{}/analysis/query/file_hash.json".format(
                        tau_clients.NSX_DEFENDER_ANALYSIS_URLS[tau_clients.NSX_DEFENDER_DC_WESTUS]
                    ),
                    verify=True,
                ),
                call(
                    data=ANALYSIS_AUTH_DATA,
                    params=None,
                    files=None,
                    headers=None,
                    method="POST",
                    stream=False,
                    timeout=mock.ANY,
                    url="{}/authentication/login.json".format(
                        tau_clients.NSX_DEFENDER_ANALYSIS_URLS[tau_clients.NSX_DEFENDER_DC_NLEMEA]
                    ),
                    verify=True,
                ),
                call(
                    data=None,
                    params={"hash_value": "a" * 32, "hash_algorithm": "md5"},
                    files=None,
                    headers=None,
                    method="GET",
                    stream=False,
                    timeout=mock.ANY,
                    url="{}/analysis/query/file_hash.json".format(
                        tau_clients.NSX_DEFENDER_ANALYSIS_URLS[tau_clients.NSX_DEFENDER_DC_NLEMEA]
                    ),
                    verify=True,
                ),
            ]
        )
        self.assertEqual(ret, expected_result)

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_multi_analysis_client__multi_dispatch__wrong_init(self, requests_mock, session_mock):
        """Test the multi analysis client with multi dispatch when wrong init is called."""
        expected_result = {"progress": 100, "completed": 1}
        result = {"progress": 100, "completed": 1}
        session_mock.request.side_effect = [
            mock_response(200, {"success": 1, "data": "true"}),
            mock_response(200, {"success": 1, "data": result}),
        ]
        requests_mock.session.return_value = session_mock
        # Test the code
        client = nsx_defender.MultiAnalysisClient(
            api_url=tau_clients.NSX_DEFENDER_ANALYSIS_URLS[tau_clients.NSX_DEFENDER_DC_WESTUS],
            login_params=ANALYSIS_AUTH_DATA,
        )
        ret = client.query_file_hash("a" * 32)
        # Verify the asserts
        session_mock.request.assert_has_calls(
            [
                call(
                    data=ANALYSIS_AUTH_DATA,
                    params=None,
                    files=None,
                    headers=None,
                    method="POST",
                    stream=False,
                    timeout=mock.ANY,
                    url="{}/authentication/login.json".format(
                        tau_clients.NSX_DEFENDER_ANALYSIS_URLS[tau_clients.NSX_DEFENDER_DC_WESTUS]
                    ),
                    verify=True,
                ),
                call(
                    data=None,
                    params={"hash_value": "a" * 32, "hash_algorithm": "md5"},
                    files=None,
                    headers=None,
                    method="GET",
                    stream=False,
                    timeout=mock.ANY,
                    url="{}/analysis/query/file_hash.json".format(
                        tau_clients.NSX_DEFENDER_ANALYSIS_URLS[tau_clients.NSX_DEFENDER_DC_WESTUS]
                    ),
                    verify=True,
                ),
            ]
        )
        self.assertEqual(ret, expected_result)

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_multi_analysis_client__multi_dispatch__reset(self, requests_mock, session_mock):
        """Test the multi analysis client with multi dispatch but the internal struct is reset."""
        expected_result = {"progress": 100, "completed": 1}
        result = {"progress": 100, "completed": 1}
        session_mock.request.side_effect = [
            mock_response(200, {"success": 1, "data": "true"}),
            mock_response(200, {"success": 1, "data": result}),
        ]
        requests_mock.session.return_value = session_mock
        # Test the code
        client = nsx_defender.MultiAnalysisClient.from_conf(self.conf, "analysis")
        client.available_clients = {}
        ret = client.query_file_hash("a" * 32)
        # Verify the asserts
        session_mock.request.assert_has_calls(
            [
                call(
                    data=ANALYSIS_AUTH_DATA,
                    params=None,
                    files=None,
                    headers=None,
                    method="POST",
                    stream=False,
                    timeout=mock.ANY,
                    url="{}/authentication/login.json".format(
                        tau_clients.NSX_DEFENDER_ANALYSIS_URLS[tau_clients.NSX_DEFENDER_DC_WESTUS]
                    ),
                    verify=True,
                ),
                call(
                    data=None,
                    params={"hash_value": "a" * 32, "hash_algorithm": "md5"},
                    files=None,
                    headers=None,
                    method="GET",
                    stream=False,
                    timeout=mock.ANY,
                    url="{}/analysis/query/file_hash.json".format(
                        tau_clients.NSX_DEFENDER_ANALYSIS_URLS[tau_clients.NSX_DEFENDER_DC_WESTUS]
                    ),
                    verify=True,
                ),
            ]
        )
        self.assertEqual(ret, expected_result)

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_multi_analysis_client__single_dispatch(self, requests_mock, session_mock):
        """Test the multi analysis client with a single dispatch method."""
        expected_result = {"progress": 100, "completed": 1}
        result = {"progress": 100, "completed": 1}
        session_mock.request.side_effect = [
            mock_response(200, {"success": 1, "data": "true"}),
            mock_response(200, {"success": 1, "data": result}),
        ]
        requests_mock.session.return_value = session_mock
        # Test the code
        client = nsx_defender.MultiAnalysisClient.from_conf(self.conf, "analysis")
        ret = client.get_progress(TEST_UUID)
        # Verify the asserts
        session_mock.request.assert_has_calls(
            [
                call(
                    data=ANALYSIS_AUTH_DATA,
                    params=None,
                    files=None,
                    headers=None,
                    method="POST",
                    stream=False,
                    timeout=mock.ANY,
                    url="{}/authentication/login.json".format(
                        tau_clients.NSX_DEFENDER_ANALYSIS_URLS[tau_clients.NSX_DEFENDER_DC_WESTUS]
                    ),
                    verify=True,
                ),
                call(
                    data=None,
                    params={"uuid": TEST_UUID},
                    files=None,
                    headers=None,
                    method="GET",
                    stream=False,
                    timeout=mock.ANY,
                    url="{}/analysis/get_progress.json".format(
                        tau_clients.NSX_DEFENDER_ANALYSIS_URLS[tau_clients.NSX_DEFENDER_DC_WESTUS]
                    ),
                    verify=True,
                ),
            ]
        )
        self.assertEqual(ret, expected_result)

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_multi_analysis_client__properties(self, requests_mock, session_mock):
        """Test the multi analysis client when accessing properties."""
        requests_mock.session.return_value = session_mock
        # Test the code
        client = nsx_defender.MultiAnalysisClient.from_conf(self.conf, "analysis")
        self.assertEqual(
            client.base,
            tau_clients.NSX_DEFENDER_ANALYSIS_URLS[tau_clients.NSX_DEFENDER_DC_WESTUS],
        )


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python
# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import json
import unittest
from typing import Dict
from typing import Optional
from typing import Union
from unittest.mock import call

import ddt
import mock
import requests.exceptions
from tau_clients import exceptions
from tau_clients import nsx_defender


PORTAL_AUTH_DATA = {"username": "asd", "password": "dsa"}

ANALYSIS_AUTH_DATA = {"key": "asd", "api_token": "dsa"}

TEST_UUID = "a" * 32

TEST_API_URL = "https://<base>"


def mock_response(
    status_code: int, content: Optional[Union[str, Dict]] = None
) -> requests.Response:
    """
    Mock response.

    :param int status_code: the HTTP response code
    :param dict|str|None content: the option content
    :rtype: requests.Response
    :return: the mocked response
    """
    res = requests.Response()
    res.status_code = status_code
    res.url = TEST_API_URL
    res.reason = "code"
    if content:
        res._content = json.dumps(content).encode("utf-8")
    return res


@ddt.ddt
class AbstractClientTestCase(unittest.TestCase):
    """Test some utilities."""

    @ddt.data(
        (("login", []), "{}/login.json".format(TEST_API_URL)),
        (("login", []), "{}/login.json".format(TEST_API_URL)),
        (("analysis", ["test"]), "{}/analysis/test.json".format(TEST_API_URL)),
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
        client = nsx_defender.PortalClient(
            api_url=TEST_API_URL, login_params=ANALYSIS_AUTH_DATA
        )
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
        client = nsx_defender.PortalClient(
            api_url=TEST_API_URL, login_params=PORTAL_AUTH_DATA
        )
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
        client = nsx_defender.PortalClient(
            api_url=TEST_API_URL, login_params=PORTAL_AUTH_DATA
        )
        with self.assertRaisesRegexp(exceptions.ApiError, exception_msg_regex):
            _ = client.get_progress(TEST_UUID)

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_open_client__api_http_error(self, requests_mock, session_mock):
        """Test the portal client when there is a HTTP error and some API error data."""
        exception_msg_regex = (
            r"API Error \(3000\) \(500 Server "
            r"Error: code for url: {}\)".format(TEST_API_URL)
        )
        session_mock.request.side_effect = [
            mock_response(500, {"success": 0, "error_code": 3000, "error": "API Error"})
        ]
        requests_mock.session.return_value = session_mock

        # Test the code
        client = nsx_defender.PortalClient(
            api_url=TEST_API_URL, login_params=PORTAL_AUTH_DATA
        )
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
        client = nsx_defender.PortalClient(
            api_url=TEST_API_URL, login_params=PORTAL_AUTH_DATA
        )
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
        client = nsx_defender.PortalClient(
            api_url=TEST_API_URL, login_params=PORTAL_AUTH_DATA
        )
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


if __name__ == "__main__":
    unittest.main()

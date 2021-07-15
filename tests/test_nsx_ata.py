import json
import unittest
from unittest.mock import call

import mock
import requests.exceptions
from tau_clients import exceptions
from tau_clients import nsx_ata


PORTAL_AUTH_DATA = {"username": "asd", "password": "dsa"}

ANALYSIS_AUTH_DATA = {"key": "asd", "api_token": "dsa"}

TEST_UUID = "a" * 32

TEST_API_URL = "https://<base>"


def mock_response(status_code, content=None):
    res = requests.Response()
    res.status_code = status_code
    res.url = TEST_API_URL
    res.reason = "code"
    if content:
        res._content = json.dumps(content).encode("utf-8")
    return res


class OpenAnalysisTestCase(unittest.TestCase):
    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_analysis_client__request_exception(self, requests_mock, session_mock):
        exception_message = "timeout"
        session_mock.request.side_effect = [requests.ReadTimeout(exception_message)]
        requests_mock.session.return_value = session_mock

        # Test the code
        client = nsx_ata.AnalysisClient(
            api_url=TEST_API_URL, login_params=ANALYSIS_AUTH_DATA
        )
        with self.assertRaisesRegexp(exceptions.CommunicationError, exception_message):
            _ = client.get_analysis_tags(TEST_UUID)

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_analysis_client(self, requests_mock, session_mock):
        expected_result = {"progress": 100, "completed": 1}
        session_mock.request.side_effect = [
            mock_response(200, {"success": "1", "data": "true"}),
            mock_response(200, {"success": "1", "data": expected_result}),
        ]
        requests_mock.session.return_value = session_mock

        # Test the code
        client = nsx_ata.AnalysisClient(
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


class MyTestCase(unittest.TestCase):
    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_open_client__request_exception(self, requests_mock, session_mock):
        exception_message = "timeout"
        session_mock.request.side_effect = [requests.ReadTimeout(exception_message)]
        requests_mock.session.return_value = session_mock

        # Test the code
        client = nsx_ata.PortalClient(
            api_url=TEST_API_URL, login_params=PORTAL_AUTH_DATA
        )
        with self.assertRaisesRegexp(exceptions.CommunicationError, exception_message):
            _ = client.get_progress(TEST_UUID)

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_open_client__http_error(self, requests_mock, session_mock):
        exception_msg_regex = (
            r"No success field in response \(500 Server "
            r"Error: code for url: {}\)".format(TEST_API_URL)
        )
        session_mock.request.side_effect = [mock_response(500, "generic error")]
        requests_mock.session.return_value = session_mock

        # Test the code
        client = nsx_ata.PortalClient(
            api_url=TEST_API_URL, login_params=PORTAL_AUTH_DATA
        )
        with self.assertRaisesRegexp(exceptions.ApiError, exception_msg_regex):
            _ = client.get_progress(TEST_UUID)

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_open_client__api_http_error(self, requests_mock, session_mock):
        exception_msg_regex = (
            r"API Error \(3000\) \(500 Server "
            r"Error: code for url: {}\)".format(TEST_API_URL)
        )
        session_mock.request.side_effect = [
            mock_response(500, {"success": 0, "error_code": 3000, "error": "API Error"})
        ]
        requests_mock.session.return_value = session_mock

        # Test the code
        client = nsx_ata.PortalClient(
            api_url=TEST_API_URL, login_params=PORTAL_AUTH_DATA
        )
        with self.assertRaisesRegexp(exceptions.ApiError, exception_msg_regex):
            _ = client.get_progress(TEST_UUID)

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_open_client__api_error(self, requests_mock, session_mock):
        exception_msg_regex = r"Authentication Error \(3004\)"
        session_mock.request.side_effect = [
            mock_response(
                200, {"success": 0, "error_code": 3004, "error": "Authentication Error"}
            )
        ]
        requests_mock.session.return_value = session_mock

        # Test the code
        client = nsx_ata.PortalClient(
            api_url=TEST_API_URL, login_params=PORTAL_AUTH_DATA
        )
        with self.assertRaisesRegexp(exceptions.ApiError, exception_msg_regex):
            _ = client.get_progress(TEST_UUID)

    @mock.patch("requests.sessions.Session")
    @mock.patch("requests.sessions")
    def test_open_client(self, requests_mock, session_mock):
        expected_result = {"progress": 100, "completed": 1}
        session_mock.request.side_effect = [
            mock_response(200, {"success": "1", "data": "true"}),
            mock_response(200, {"success": "1", "data": expected_result}),
        ]
        requests_mock.session.return_value = session_mock

        # Test the code
        client = nsx_ata.PortalClient(
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


if __name__ == "__main__":
    unittest.main()

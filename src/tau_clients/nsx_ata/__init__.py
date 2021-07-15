import abc
import configparser
import datetime
import io
import logging

import more_itertools
import requests
import tau_clients
from tau_clients import exceptions


class AbstractClient(abc.ABC):
    """"A very basic HTTP client providing basic functionality."""

    __metaclass__ = abc.ABCMeta

    SUB_APIS = ("analysis", "authentication", "knowledgebase", "login")
    FORMATS = ["json", "xml"]

    @classmethod
    def get_login_params(cls, conf, section_name):
        """
        Get the module configuration from a ConfigParser object.

        :param ConfigParser conf: the conf object
        :param str section_name: the section name
        :rtype: dict[str, str]
        :return: the parsed configuration
        """
        api_key = conf.get(section_name, "key", fallback=None)
        api_token = conf.get(section_name, "api_token", fallback=None)
        username = conf.get(section_name, "username", fallback=None)
        password = conf.get(section_name, "password", fallback=None)
        if api_key and api_token:
            return {"key": api_key, "api_token": api_token}
        elif username and password:
            return {"username": username, "password": password}
        else:
            raise configparser.NoOptionError("username", section_name)

    @classmethod
    def client_from_config(cls, conf, section_name):
        """
        Get the client from a conf object

        :param ConfigParser conf: the conf object
        :param str section_name: the section name
        """
        url = conf.get(section_name, "url").strip("/")
        login_params = cls.get_login_params(conf, section_name)
        timeout = conf.getint(section_name, "timeout", fallback=60)
        verify_ssl = conf.getboolean(section_name, "verify_ssl", fallback=True)
        return cls(
            api_url=url,
            login_params=login_params,
            timeout=timeout,
            verify_ssl=verify_ssl,
        )

    def __init__(self, api_url, login_params, timeout=60, verify_ssl=True):
        """
        Instantiate a Lastline mini client.

        :param str api_url: the URL of the API
        :param dict[str, str]: the login parameters
        :param int timeout: the timeout
        :param boolean verify_ssl: whether to verify the SSL certificate
        """
        self._url = api_url
        self._login_params = login_params
        self._timeout = timeout
        self._verify_ssl = verify_ssl
        self._session = None
        self._logger = logging.getLogger(__name__)

    @abc.abstractmethod
    def _login(self):
        """Login using account-based or key-based methods."""

    def _is_logged_in(self):
        """Return whether we have an active session."""
        return self._session is not None

    @classmethod
    def _parse_response(cls, response):
        """
        Parse the response.

        :param requests.Response response: the response
        :rtype: tuple(str|None, Error|ApiError)
        :return: a tuple with mutually exclusive fields (either the response or the error)
        """
        try:
            ret = response.json()
            if "success" not in ret:
                return None, exceptions.ApiError("No success field in response")

            if not ret["success"]:
                return (
                    None,
                    exceptions.ApiError(ret.get("error"), ret.get("error_code")),
                )

            if "data" not in ret:
                return None, exceptions.ApiError("No data field in response")

            return ret["data"], None
        except ValueError as e:
            return None, exceptions.ApiError("Response not json {}".format(e))

    @classmethod
    def _parse_request_exception(cls, request_exception, response):
        """
        Convert an exception into a ApiError exception

        :param Exception e: the exception that has been raised
        :param Response response: the response object
        :rtype: ApiError
        :return: our exception
        """
        _, api_exception = cls._parse_response(response)
        if api_exception:
            error_message = "{} ({})".format(api_exception, request_exception)
        else:
            error_message = str(request_exception)
        return exceptions.ApiError(error_message)

    def _handle_response(self, response, raw=False):
        """
        Check a response for issues and parse the return.

        :param requests.Response response: the response
        :param boolean raw: whether the raw body should be returned
        :rtype: str
        :return: if raw, return the response content; if not raw, the data field
        :raises: CommunicationError, ApiError
        """
        # Check for HTTP errors, and re-raise in case
        try:
            response.raise_for_status()
        except requests.RequestException as exception:
            # Convert a RequestException into a ApiError
            raise self._parse_request_exception(exception, response) from exception

        # Otherwise return the data (either parsed or not) but reraise if we have an API error
        if raw:
            return response.content
        else:
            data, error = self._parse_response(response)
            if error:
                raise error
            else:
                return data

    def _build_url(self, sub_api, parts, requested_format="json"):
        if sub_api not in self.SUB_APIS:
            raise exceptions.InvalidArgument(sub_api)
        if requested_format not in self.FORMATS:
            raise exceptions.InvalidArgument(requested_format)
        num_parts = 2 + len(parts)
        pattern = "/".join(["%s"] * num_parts) + ".%s"
        params = [self._url, sub_api] + parts + [requested_format]
        return pattern % tuple(params)

    def post(self, module, function, params=None, data=None, files=None, fmt="json"):
        return self._request(
            "POST", module, function, params=params, data=data, files=files, fmt=fmt
        )

    def get(self, module, function, params=None, fmt="json"):
        return self._request("GET", module, function, params=params, fmt=fmt)

    def _request(
        self, method, module, function, params, data=None, files=None, fmt="json"
    ):
        if isinstance(function, list):
            functions = function
        else:
            functions = [function] if function else []
        url = self._build_url(module, functions, requested_format=fmt)
        return self.do_request(
            method, url, params=params, data=data, files=files, fmt=fmt
        )

    def do_request(
        self,
        method,
        url,
        params=None,
        data=None,
        files=None,
        fmt="json",
        raw=False,
        raw_response=False,
        headers=None,
        stream_response=False,
    ):
        try:
            fmt = fmt.lower().strip()
        except AttributeError:
            pass

        if fmt and fmt not in self.FORMATS:
            raise exceptions.InvalidArgument(
                "Only {} supported".format(",".join(self.FORMATS))
            )

        if fmt != "json" and not raw:
            raise exceptions.InvalidArgument("Non-json format requires raw=True")

        if method not in {"POST", "GET"}:
            raise exceptions.InvalidArgument("Only POST and GET supported")

        if not self._is_logged_in():
            self._login()

        try:
            response = self._session.request(
                method=method,
                url=url,
                data=data,
                params=params,
                files=files,
                verify=self._verify_ssl,
                timeout=self._timeout,
                stream=stream_response,
                headers=headers,
            )
        except requests.RequestException as e:
            raise exceptions.CommunicationError(str(e)) from e

        if raw_response:
            return response
        return self._handle_response(response, raw)


class PortalClient(AbstractClient):
    """Simple client to query the user portal API (PAPI)."""

    FMT_KB = "%Y-%m-%d %H:%M:%S"

    def _login(self):
        """Implement interface (portal client relies on 'username' and 'password')."""
        if self._session is None:
            self._session = requests.sessions.session()
        self.post("login", function=None, data=self._login_params)

    def get_tasks_from_knowledgebase(self, query_string, **kwargs):
        """
        Query tasks from the knowledgebase.

        :param str query_string: the query string
        :param kwargs: additional key worded arguments
        :rtype: list[dict[str, any]]
        :return: a list of tasks like:
            [
                {
                    'av_label': 'trojan.hacktoolx',
                    'severity': 'malicious',
                    'submission': '2021-02-01 13:54:08',
                    'report_uuid': '81d380b96ee66a67jGopBDj3XvjaOWW65lTrMMZ9k0YL3Uzp7Aaq',
                    'file_type': 'PeExeFile',
                    'analysis_env': 'Microsoft Windows 10',
                    'visibility': 'public',
                    'file_mime': 'application/x-pe-app-32bit-i386',
                    'task_uuid': 'dbc8b217c32a00102d2f5c684d666f47',
                    'score': 100,
                    'artifact': 'ba81b98f00168b86578e5f5de93d26ed83769432',
                    'artifact_type': 'file',
                    'backend_uuid': '483aaa39d1b84c24a2cb597bd920c0bc'
                }
            ]
        """
        if not query_string:
            return []
        malscape_tasks = self.get(
            module="knowledgebase",
            function="query_malscape_tasks",
            params={"query_string": query_string, **kwargs},
        ).get("tasks", [])
        return sorted(
            more_itertools.unique_everseen(
                iterable=malscape_tasks, key=lambda x: x["task_uuid"]
            ),
            key=lambda x: datetime.datetime.strptime(
                x["submission"], tau_clients.DATETIME_FMT
            ),
            reverse=True,
        )

    def get_progress(self, uuid):
        """
        Get the completion progress of a given task.

        :param str uuid: the unique identifier of the submitted task
        :rtype: dict[str, int]
        :return: a dictionary like:
            {
                "completed": 1,
                "progress": 100
            }
        """
        params = tau_clients.purge_none({"uuid": uuid})
        return self.get("analysis", "get_progress", params=params)

    def get_result(self, uuid):
        """
        Get report results for a given task.

        :param str uuid: the unique identifier of the submitted task
        :rtype: dict[str, any]
        :return: a dictionary containing the analysis report
        """
        params = tau_clients.purge_none({"uuid": uuid, "report_format": "json"})
        return self.get("analysis", "get_result", params=params)

    def submit_url(self, url, referer=None, user_agent=None, bypass_cache=False):
        """
        Upload an URL to be analyzed.

        :param str url: the url to analyze
        :param str|None referer: the referer
        :param str|None user_agent: the user agent
        :param boolean bypass_cache: bypass_cache
        :rtype: dict[str, any]
        :return: a dictionary like:
            {
                "submission": "2019-11-17 09:33:23",
                "child_tasks": [...],
                "reports": [...],
                "submission_timestamp": "2019-11-18 16:11:04",
                "task_uuid": "86097fb8e4cd00100464cb001b97ecbe",
                "score": 0,
                "analysis_subject": {
                    "url": "https://www.google.com"
                },
                "last_submission_timestamp": "2019-11-18 16:11:04"
            }

            OR the following if the analysis is still pending:

            {
                "submission_timestamp": "2019-11-18 13:59:25",
                "task_uuid": "f3c0ae115d51001017ff8da768fa6049",
            }
        """
        data = tau_clients.purge_none(
            {
                "url": url,
                "bypass_cache": bypass_cache,
                "referer": referer,
                "user_agent": user_agent,
            }
        )
        return self.post("analysis", "submit_url", data=data)

    def submit_file(
        self,
        file_data,
        file_name=None,
        password=None,
        analysis_env=None,
        allow_network_traffic=True,
        bypass_cache=False,
    ):
        """
        Upload a file to be analyzed.

        :param bytes file_data: the data as a byte sequence
        :param str|None file_name: if set, represents the name of the file to submit
        :param str|None password: if set, use it to extract the sample
        :param str|None analysis_env: if set, e.g windowsxp
        :param boolean allow_network_traffic: if set to False, deny network connections
        :param boolean bypass_cache: whether to re-process a file (requires special permissions)
        :rtype: dict[str, any]
        :return: a dictionary like:
            {
                "submission": "2019-11-17 09:33:23",
                "child_tasks": [...],
                "reports": [...],
                "submission_timestamp": "2019-11-18 16:11:04",
                "task_uuid": "86097fb8e4cd00100464cb001b97ecbe",
                "score": 0,
                "analysis_subject": {
                    "url": "https://www.google.com"
                },
                "last_submission_timestamp": "2019-11-18 16:11:04"
            }

            OR the following if the analysis is still pending:

            {
                "submission_timestamp": "2019-11-18 13:59:25",
                "task_uuid": "f3c0ae115d51001017ff8da768fa6049",
            }
        """
        data = tau_clients.purge_none(
            {
                "filename": file_name,
                "password": password,
                "analysis_env": analysis_env,
                "allow_network_traffic": allow_network_traffic,
                "bypass_cache": bypass_cache,
            }
        )
        files = {"file": (file_name, file_data, "application/octet-stream")}
        return self.post("analysis", "submit_file", data=data, files=files)


class AnalysisClient(AbstractClient):
    """"Simple client to query the analysis API (Malscape)."""

    def _login(self):
        """Implement interface (analysis client relies on 'key' and 'api_token')."""
        if self._session is None:
            self._session = requests.sessions.session()
        self.post(
            "authentication", "login", data=tau_clients.purge_none(self._login_params)
        )

    def query_file_hash(self, file_hash):
        """
        Search for existing analysis results with the given file hash.

        :param str file_hash: the file hash
        :rtype: dict[str, any]
        :return: a dictionary like:
            {
                'tasks': [
                    {
                        'expires': '2021-02-01 14:54:09',
                        'file_sha1': 'ba81b98f00168b86578e5f5de93d26ed83769432',
                        'file_md5': '25ea2092ffc29fde64175a19a5795bf7',
                        'task_uuid': 'dbc8b217c32a00102d2f5c684d666f47',
                        'score': 100,
                        'file_sha256': '9f247f42114e7449b3dc5ed99ee706fbe1f239afb5beff279824bc67d83afba9'
                    }
                ],
                'files_found': 1
            }
        """
        hash_type = tau_clients.get_hash_type(file_hash)
        if not hash_type:
            raise exceptions.InvalidArgument("Hash type not recognized")
        params = tau_clients.purge_none(
            {"hash_value": file_hash, "hash_algorithm": hash_type}
        )
        return self.get("analysis", ["query", "file_hash"], params=params)

    def get_analysis_tags(self, uuid, allow_datacenter_redirect=None):
        """
        Get the analysis tags for an analysis task.

        :param str uuid: the unique identifier of the submitted task
        :param bool allow_datacenter_redirect: whether to allow data center redirection
        :rtype: dict[str, any]
        :return: a dictionary like:
            {
                'task_uuid': 'dbc8b217c32a00102d2f5c684d666f47',
                'analysis_tags': [
                    {
                        'data': {
                            'score': 45,
                            'type': 'activity',
                            'value': 'Anomaly: AI detected possible malicious code reuse'
                        },
                        'format': 'typed_tag'
                    },
                    {
                        'data': {
                            'score': 70,
                            'type': 'activity',
                            'value': 'Execution: Ability to download and execute commands from memory via PowerShell'
                        },
                        'format': 'typed_tag'
                    },
                    {
                        'data': {
                            'score': 100,
                            'type': 'av_family',
                            'value': 'hacktoolx'
                        },
                        'format': 'typed_tag'
                    },
                    {
                        'data': {
                            'score': 100,
                            'type': 'av_class',
                            'value': 'trojan'
                        },
                        'format': 'typed_tag'
                    },
                ]
            }
        """
        params = tau_clients.purge_none(
            {"uuid": uuid, "allow_datacenter_redirect": allow_datacenter_redirect}
        )
        return self.get("analysis", "get_analysis_tags", params=params)

    def get_progress(self, uuid):
        """
        Get the completion progress of a given task.

        :param str uuid: the unique identifier of the submitted task
        :rtype: dict[str, int]
        :return: a dictionary like:
            {
                "completed": 1,
                "progress": 100
            }
        """
        params = {"uuid": uuid}
        return self.get("analysis", "get_progress", params=params)

    def get_completed(self, after, before=None, include_score=False):
        """
        Get the list of uuids of tasks that were completed within a given time frame.

        :param datetime.datetime|str after: request tasks completed after this time
        :param datetime.datetime|str|None before: request tasks completed before this time
        :param include_score: if True, the response contains score
        :return: a dictionary like:
            {
                'tasks': ['182a645e7020001000de1474baf8b7b9'],
                'after': '2021-07-14 09:10:00',
                'more_results_available': 0,
                'resume': '2021-07-14 14:09:47',
                'before': '2021-07-14 14:09:59'
            }
        """
        if hasattr(before, "strftime"):
            before = before.strftime(tau_clients.DATETIME_FMT)
        if hasattr(after, "strftime"):
            after = after.strftime(tau_clients.DATETIME_FMT)
        params = tau_clients.purge_none(
            {
                "before": before,
                "after": after,
                "include_score": include_score and 1 or 0,
            }
        )
        return self.get("analysis", "completed", params=params)

    def get_result(self, uuid):
        """
        Get report results for a given task.

        :param str uuid: the unique identifier of the submitted task
        :rtype: dict[str, any]
        :rtype: dict[str, any]
        :return: a dictionary containing the analysis report
        """
        params = {"uuid": uuid}
        return self.get("analysis", "get", params=params)

    def submit_file(
        self,
        file_data,
        file_name=None,
        password=None,
        analysis_env=None,
        allow_network_traffic=True,
        bypass_cache=False,
        include_report=False,
    ):
        """
        Upload a file to be analyzed.

        :param bytes file_data: the data as a byte sequence
        :param str|None file_name: if set, represents the name of the file to submit
        :param str|None password: if set, use it to extract the sample
        :param str|None analysis_env: if set, e.g windowsxp
        :param boolean allow_network_traffic: if set to False, deny network connections
        :param boolean bypass_cache: whether to re-process a file (requires special permissions)
        :rtype: dict[str, any]
        :return: a dictionary in the following form if the analysis is already available:
            {
                "submission": "2019-11-17 09:33:23",
                "child_tasks": [...],
                "reports": [...],
                "submission_timestamp": "2019-11-18 16:11:04",
                "task_uuid": "86097fb8e4cd00100464cb001b97ecbe",
                "score": 0,
                "analysis_subject": {
                    "url": "https://www.google.com"
                },
                "last_submission_timestamp": "2019-11-18 16:11:04"
            }

            OR the following if the analysis is still pending:

            {
                "submission_timestamp": "2019-11-18 13:59:25",
                "task_uuid": "f3c0ae115d51001017ff8da768fa6049",
            }
        """
        data = tau_clients.purge_none(
            {
                "bypass_cache": bypass_cache and 1 or None,
                "analysis_env": analysis_env,
                "allow_network_traffic": allow_network_traffic and 1 or None,
                "filename": file_name,
                "password": password,
                "full_report_score": -1,
            }
        )
        files = tau_clients.purge_none(
            {
                # If an explicit filename was provided, we can pass it down to
                # python-requests to use it in the multipart/form-data. This avoids
                # having python-requests trying to guess the filename based on stream
                # attributes.
                #
                # The problem with this is that, if the filename is not ASCII, then
                # this triggers a bug in flask/werkzeug which means the file is
                # thrown away. Thus, we just force an ASCII name
                "file": ("dummy-ascii-name-for-file-param", io.BytesIO(file_data))
            }
        )
        ret_data = self.post("analysis", ["submit", "file"], data=data, files=files)
        if not include_report:
            ret_data.pop("report", None)
        return ret_data

    def submit_url(
        self,
        url,
        referer=None,
        user_agent=None,
        bypass_cache=False,
        include_report=False,
    ):
        """
        Upload an URL to be analyzed.

        :param str url: the url to analyze
        :param str|None referer: the referer
        :param str|None user_agent: the user agent
        :param boolean bypass_cache: bypass_cache
        :param boolean include_report: whether to include the report in the result
        :rtype: dict[str, any]
        :return: a dictionary like the following if the analysis is already available:
            {
                "submission": "2019-11-17 09:33:23",
                "child_tasks": [...],
                "reports": [...],
                "submission_timestamp": "2019-11-18 16:11:04",
                "task_uuid": "86097fb8e4cd00100464cb001b97ecbe",
                "score": 0,
                "analysis_subject": {
                    "url": "https://www.google.com"
                },
                "last_submission_timestamp": "2019-11-18 16:11:04"
            }

            OR the following if the analysis is still pending:

            {
                "submission_timestamp": "2019-11-18 13:59:25",
                "task_uuid": "f3c0ae115d51001017ff8da768fa6049",
            }
        """
        data = tau_clients.purge_none(
            {
                "url": url,
                "referer": referer,
                "bypass_cache": bypass_cache and 1 or None,
                "user_agent": user_agent or None,
            }
        )
        ret_data = self.post("analysis", ["submit", "url"], data=data)
        if not include_report:
            ret_data.pop("report", None)
        return ret_data

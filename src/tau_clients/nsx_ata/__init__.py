"""
:Copyright:
    Copyright 2021 VMware, Inc.  All Rights Reserved.
"""
import abc
import configparser
import datetime
import io
import logging
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Union

import more_itertools
import requests
import tau_clients
from tau_clients import exceptions


class AbstractClient(abc.ABC):
    """"A very basic HTTP client providing basic functionality."""

    __metaclass__ = abc.ABCMeta

    # Empty tuple, to be overriden by the subclass
    MODULES = ()

    # Empty tuple, to be overriden by the subclass
    FORMATS = ()

    # Default FMT used by the API
    DATETIME_FMT = "%Y-%m-%d %H:%M:%S"

    @classmethod
    def _get_login_params(
        cls, conf: configparser.ConfigParser, section_name: str
    ) -> dict:
        """
        Get the login parameters from a 'ConfigParser' object.

        Note: depending on the license type we might be using username/password combination
            of key/api_token; this method makes sure that at least one combination is selected

        :param configparser.ConfigParser conf: the conf object
        :param str section_name: the section name
        :rtype: dict[str, str]
        :return: a dictionary with the required login parameters
        :raises configparser.NoOptionError: when no valid combination is found
        :raises configparser.Error: any exception that can be raised by ConfigParser
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
    def from_conf(
        cls, conf: configparser.ConfigParser, section_name: str
    ) -> "AbstractClient":
        """
        Get the client from a 'ConfigParser' object.

        :param configparser.ConfigParser conf: the conf object
        :param str section_name: the section name
        :rtype: Any
        :return: the initialized client
        :raises configparser.Error: any exception that can be raised by ConfigParser
        """
        url = conf.get(section_name, "url").strip("/")
        login_params = cls._get_login_params(conf, section_name)
        timeout = conf.getint(section_name, "timeout", fallback=60)
        verify_ssl = conf.getboolean(section_name, "verify_ssl", fallback=True)
        return cls(
            api_url=url,
            login_params=login_params,
            timeout=timeout,
            verify_ssl=verify_ssl,
        )

    def __init__(
        self,
        api_url: str,
        login_params: Dict[str, str],
        timeout: int = 60,
        verify_ssl: bool = True,
    ) -> None:
        """
        Constructor.

        :param str api_url: the URL of the API endpoint
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

    @property
    def base(self) -> str:
        """Return the API endpoint URL."""
        return self._url

    @abc.abstractmethod
    def _login(self) -> None:
        """Login using account-based or key-based methods."""

    def _is_logged_in(self) -> bool:
        """Return whether we have an active session."""
        return self._session is not None

    def _build_url(
        self, module: str, function: Union[List[str], str], fmt: str = "json"
    ) -> str:
        """
        Build a URL composed by module, function(s), and format.

        :param str module: the module that is being contacted
        :param list[str]|str function: a list of strings detailing the function required
        :param str fmt: the format of the API call
        :rtype: str
        :return: the URL ready to be contacted
        :raises InvalidArgument: if any of the arguments is not valid
        """
        if module not in self.MODULES:
            raise exceptions.InvalidArgument(module)
        if fmt not in self.FORMATS:
            raise exceptions.InvalidArgument(fmt)
        if isinstance(function, list):
            parts = function
        else:
            parts = [function] if function else []
        if parts and not any(isinstance(x, str) for x in parts):
            raise exceptions.InvalidArgument(function)
        return "/".join([self.base, module] + parts) + ".{}".format(fmt)

    @classmethod
    def _parse_response(cls, response: requests.Response) -> Union[dict, str]:
        """
        Parse the response.

        :param requests.Response response: the response
        :rtype: dict|str
        :return: the decoded response
        :raises ApiError: if the response has an error
        """
        try:
            ret = response.json()
            if "success" not in ret:
                raise exceptions.ApiError("No success field in response")
            if not ret["success"]:
                raise exceptions.ApiError(ret.get("error"), ret.get("error_code"))
            if "data" not in ret:
                raise exceptions.ApiError("No data field in response")
            return ret["data"]
        except ValueError as e:
            raise exceptions.ApiError("Response not json {}".format(e))

    @classmethod
    def _parse_exception(
        cls, request_exception: requests.RequestException, response: requests.Response
    ) -> exceptions.ApiError:
        """
        Convert an exception into a ApiError exception.

        :param requests.RequestException request_exception: the exception that has been raised
        :param requests.Response response: the response object
        :rtype: ApiError
        :return: the converted exception with as much debug info as possible
        """
        try:
            cls._parse_response(response)
        except exceptions.ApiError as api_exception:
            error_message = "{} ({})".format(api_exception, request_exception)
        else:
            error_message = str(request_exception)
        return exceptions.ApiError(error_message)

    @classmethod
    def _handle_response(
        cls, response: requests.Response, raw: bool = False
    ) -> Union[dict, str]:
        """
        Check a response for issues and parse the return.

        :param requests.Response response: the response
        :param bool raw: whether the raw body should be returned
        :rtype: str|dict
        :return: the response content
        :raises ApiError: in case of any error
        """
        try:
            response.raise_for_status()
        except requests.RequestException as exception:
            raise cls._parse_exception(exception, response) from exception

        if raw:
            return response.content
        else:
            return cls._parse_response(response)

    def _request(
        self,
        method: str,
        module: str,
        function: Union[List[str], str],
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, str]] = None,
        raw: bool = False,
        raw_response: bool = False,
        stream_response: bool = False,
        fmt: str = "json",
    ) -> Union[dict, str]:
        """
        Do the request (and authenticate first if needed).

        :param str method: the HTTP request method
        :param str module: the module to contact
        :param list[str]|str function: a list of string (or a string) defining the route
        :param dict[str, str] params: a dictionary of parameters
        :param dict[str, str] data: used for POSTs
        :param dict[str, str] headers: headers
        :param dict[str, str] files: when downloading a file
        :param str fmt: the requested format
        :param bool raw: whether to return a non-JSON decoded response
        :param bool raw_response: whether to return a raw Response object
        :param bool stream_response: whether to download immediately
        :rtype: str|dict
        :return: the response content
        :raises CommunicationError: if there was an error connecting to the resource
        :raises ApiError: if there was on error on the server side
        """
        if not self._is_logged_in():
            self._login()

        try:
            response = self._session.request(
                method=method,
                url=self._build_url(module, function, fmt=fmt),
                params=params,
                data=data,
                headers=headers,
                files=files,
                verify=self._verify_ssl,
                timeout=self._timeout,
                stream=stream_response,
            )
        except requests.RequestException as e:
            raise exceptions.CommunicationError(str(e)) from e

        if raw_response:
            return response
        else:
            return self._handle_response(response, raw)

    def post(
        self,
        module: str,
        function: Union[List[str], str],
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, str]] = None,
        fmt: str = "json",
    ) -> Union[dict, str]:
        """Utility method to issue a POST request (see '_request' for documentation)."""
        return self._request(
            method="POST",
            module=module,
            function=function,
            params=params,
            data=data,
            files=files,
            fmt=fmt,
        )

    def get(
        self,
        module: str,
        function: Union[List[str], str],
        params: Optional[Dict[str, str]] = None,
        fmt: str = "json",
    ) -> Union[dict, str]:
        """Utility method to issue a GET request (see '_request' for documentation)."""
        return self._request(
            method="GET", module=module, function=function, params=params, fmt=fmt
        )


class PortalClient(AbstractClient):
    """Simple client to query the user portal API (PAPI)."""

    MODULES = ("analysis", "knowledgebase", "login")

    FORMATS = ("json",)

    def _login(self) -> None:
        """Implement interface (portal client relies on 'username' and 'password')."""
        if self._session is None:
            self._session = requests.sessions.session()
        self.post("login", function=None, data=self._login_params)

    def get_tasks_from_knowledgebase(
        self, query_string: str, **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Query tasks from the knowledgebase, most recent first.

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
        malscape_tasks = self.get(
            module="knowledgebase",
            function="query_malscape_tasks",
            params={"query_string": query_string, **kwargs},
        ).get("tasks", [])
        unique_malscape_tasks = more_itertools.unique_everseen(
            iterable=malscape_tasks, key=lambda x: x["task_uuid"]
        )
        sorted_malscape_tasks = sorted(
            unique_malscape_tasks,
            key=lambda x: datetime.datetime.strptime(
                x["submission"], self.DATETIME_FMT
            ),
            reverse=True,
        )
        return sorted_malscape_tasks

    def get_progress(self, uuid: str) -> Dict[str, int]:
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

    def get_result(self, uuid: str) -> Dict[str, Any]:
        """
        Get report results for a given task.

        :param str uuid: the unique identifier of the submitted task
        :rtype: dict[str, any]
        :return: a dictionary containing the analysis report
        """
        params = tau_clients.purge_none({"uuid": uuid, "report_format": "json"})
        return self.get("analysis", "get_result", params=params)

    def submit_url(
        self,
        url: str,
        referer: Optional[str] = None,
        user_agent: Optional[str] = None,
        bypass_cache: bool = False,
    ) -> Dict[str, Any]:
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
        file_data: bytes,
        file_name: Optional[str] = None,
        password: Optional[str] = None,
        analysis_env: Optional[str] = None,
        allow_network_traffic: bool = True,
        bypass_cache: bool = False,
    ) -> Dict[str, Any]:
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

    MODULES = ("analysis", "authentication")

    FORMATS = ("json", "xml")

    def _login(self) -> None:
        """Implement interface (analysis client relies on 'key' and 'api_token')."""
        if self._session is None:
            self._session = requests.sessions.session()
        self.post(
            "authentication", "login", data=tau_clients.purge_none(self._login_params)
        )

    def query_file_hash(self, file_hash: str) -> Dict[str, Any]:
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
                        'file_sha256': '9f247f42114e7449b3dc5ed99ee706fbe1f239...'
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

    def get_analysis_tags(
        self, uuid: str, allow_datacenter_redirect: bool = None
    ) -> Dict[str, Any]:
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
                            'value': 'Execution: Ability to download and execute commands'
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

    def get_progress(self, uuid: str) -> Dict[str, int]:
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

    def get_completed(
        self,
        after: Union[datetime.datetime, str],
        before: Optional[Union[datetime.datetime, str]] = None,
        include_score: bool = False,
    ) -> Dict[str, Any]:
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
            before = before.strftime(self.DATETIME_FMT)
        if hasattr(after, "strftime"):
            after = after.strftime(self.DATETIME_FMT)
        params = tau_clients.purge_none(
            {
                "before": before,
                "after": after,
                "include_score": include_score and 1 or 0,
            }
        )
        return self.get("analysis", "completed", params=params)

    def get_result(self, uuid: str) -> Dict[str, Any]:
        """
        Get report results for a given task.

        :param str uuid: the unique identifier of the submitted task
        :rtype: dict[str, any]
        :return: a dictionary containing the analysis report
        """
        params = {"uuid": uuid}
        return self.get("analysis", "get", params=params)

    def submit_file(
        self,
        file_data: bytes,
        file_name: Optional[str] = None,
        password: Optional[str] = None,
        analysis_env: Optional[str] = None,
        allow_network_traffic: bool = True,
        bypass_cache: bool = False,
        include_report: bool = False,
    ) -> Dict[str, Any]:
        """
        Upload a file to be analyzed.

        :param bytes file_data: the data as a byte sequence
        :param str|None file_name: if set, represents the name of the file to submit
        :param str|None password: if set, use it to extract the sample
        :param str|None analysis_env: if set, e.g windowsxp
        :param boolean allow_network_traffic: if set to False, deny network connections
        :param boolean bypass_cache: whether to re-process a file
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
        # We force an ASCII name to wor-around flask/werkzeug issues server side
        files = tau_clients.purge_none(
            {"file": ("dummy-ascii-name-for-file-param", io.BytesIO(file_data))}
        )
        ret_data = self.post("analysis", ["submit", "file"], data=data, files=files)
        if not include_report:
            ret_data.pop("report", None)
        return ret_data

    def submit_url(
        self,
        url: str,
        referer: Optional[str] = None,
        user_agent: Optional[str] = None,
        bypass_cache: bool = False,
        include_report: bool = False,
    ) -> Dict[str, Any]:
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

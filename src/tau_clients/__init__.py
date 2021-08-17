# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import collections
import datetime
import functools
import io
import re
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Sized
from typing import Union
from urllib import parse


# All the domains that are used whenever NSX Defender is hosted
NSX_DEFENDER_HOSTED_DOMAINS = frozenset(
    [
        "user.lastline.com",
        "user.us.lastline.com",
        "user.emea.lastline.com",
        "analysis.lastline.com",
        "analysis.us.lastline.com",
        "analysis.emea.lastline.com",
    ]
)

# These are constants representing NSX Defender data centers
NSX_DEFENDER_DC_WESTUS = "west.us"
NSX_DEFENDER_DC_NLEMEA = "nl.emea"

NSX_DEFENDER_ANALYSIS_URLS = {
    NSX_DEFENDER_DC_WESTUS: "https://analysis.us.lastline.com",
    NSX_DEFENDER_DC_NLEMEA: "https://analysis.emea.lastline.com",
}
NSX_DEFENDER_ANALYSIS_LB_URL = "https://analysis.lastline.com"

NSX_DEFENDER_PORTAL_URLS = {
    NSX_DEFENDER_DC_WESTUS: "https://user.us.lastline.com",
    NSX_DEFENDER_DC_NLEMEA: "https://user.emea.lastline.com",
}
NSX_DEFENDER_PORTAL_LB_URL = "https://user.lastline.com"


# Metadata types that can be returned from 'AnalysisClient.get_result'
METADATA_TYPE_PCAP = "traffic_capture"
METADATA_TYPE_PROCESS_SNAPSHOT = "process_snapshot"
METADATA_TYPE_YARA_STRINGS = "codehash_yara_strings"
METADATA_TYPE_CODEHASH = "codehash"
METADATA_TYPE_SCREENSHOT = "screenshot"
METADATA_TYPE_SFC = "sfc2_feature_reuse_report"

# Report types
REPORT_TYPE_SANDBOX = "ll-int-win"

# Datetime formats
DATETIME_FMT = "%Y-%m-%d %H:%M:%S"
DATETIME_MSEC_FMT = DATETIME_FMT + ".%f"
DATE_FMT = "%Y-%m-%d"


def is_likely_task_uuid(hash_like: str) -> bool:
    """
    Heuristic to check whether a string is likely a task uuid.

    :param str hash_like: the string to be tested
    :rtype: bool
    :return: whether the string is likely a task uuid
    """
    return get_hash_type(hash_like) == "md5" and re.match(r"00[1234]", hash_like[12:15])


def parse_datetime(d: str) -> datetime.datetime:
    """
    Parse a datetime.

    :param str d: the datetime in string format
    :rtype: datetime.datetime
    :return: the datetime object
    :raises ValueError: if no possible parsing was possible
    """
    for fmt in [DATETIME_MSEC_FMT, DATETIME_FMT, DATE_FMT]:
        try:
            return datetime.datetime.strptime(d, fmt)
        except ValueError:
            pass
    else:  # pylint: disable=W0120
        raise ValueError("Date '%s' does not match format '%Y-%m-%d[ %H:%M:%S[.%f]]'")


def purge_none(d: Dict[Any, Any]) -> Dict[Any, Any]:
    """Purge None entries from a dictionary."""
    return {k: v for k, v in d.items() if v is not None}


def get_hash_type(hash_value: str) -> Optional[str]:
    """Get the hash type."""
    if len(hash_value) == 32:
        return "md5"
    elif len(hash_value) == 40:
        return "sha1"
    elif len(hash_value) == 64:
        return "sha256"
    else:
        return None


def get_task_link(
    uuid: str,
    analysis_url: Optional[str] = None,
    portal_url: Optional[str] = None,
    prefer_load_balancer: bool = False,
) -> str:
    """
    Get the task link given the task uuid and at least one API url.

    Note: this method should correctly support on-premise installations as by default
        the URLs used by on-premise installations mimics hosted API URLs.

    :param str uuid: the task uuid
    :param str|None analysis_url: the URL to the analysis API endpoint
    :param str|None portal_url: the URL to the portal API endpoint
    :param bool prefer_load_balancer: if the hosted task link should point to the load balancer
    :rtype: str
    :return: the task link
    :raises ValueError: if not enough parameters have been provided
    """
    if not analysis_url and not portal_url:
        return "{}/portal#/analyst/task/{}/overview".format(NSX_DEFENDER_PORTAL_LB_URL, uuid)
    if analysis_url:
        portal_url = "{}/papi".format(analysis_url.replace("analysis.", "user."))
    portal_url_path = "../portal#/analyst/task/{}/overview".format(uuid)
    task_link = parse.urljoin(portal_url, portal_url_path)
    if is_task_link_hosted(task_link) and prefer_load_balancer:
        return task_link.replace(".us.", ".").replace(".emea.", ".")
    else:
        return task_link


def get_uuid_from_task_link(task_link: str) -> str:
    """
    Return the uuid from a task link.

    :param str task_link: a task link
    :rtype: str
    :return: the uuid
    :raises ValueError: if the link contains not task uuid
    """
    try:
        return re.findall("[a-fA-F0-9]{32}", task_link)[0]
    except IndexError:
        raise ValueError("Link does not contain a valid task uuid")  # pylint: disable=W0707


def is_task_link_hosted(task_link: str) -> bool:
    """
    Return whether the portal link is pointing to a hosted submission.

    :param str task_link: a task link
    :rtype: bool
    :return: whether the link points to a hosted analysis
    """
    for domain in NSX_DEFENDER_HOSTED_DOMAINS:
        if domain in task_link:
            return True
    return False


def merge_dicts(
    sequence_of_dict: Union[Sized, List],
    reduce_funcs: Optional[Dict[str, Callable]] = None,
) -> Dict[str, Any]:
    """
    Merge a list o dictionary using custom functions to merge values.

    :param list[dict]|sized[dict] sequence_of_dict: a sequence of dicts
    :param dict[str, callable]|None reduce_funcs: a list of reduce functions indexed by key
    :rtype: dict[str, any]
    :return: a fully merged dictionary
    """
    if len(sequence_of_dict) == 1:
        # this is necessary to support views on dictionary values
        try:
            return sequence_of_dict[0]
        except TypeError:
            return next(iter(sequence_of_dict))
    if not reduce_funcs:
        reduce_funcs = {}
    # We get the keys that are in common
    common_keys = set.intersection(*map(set, sequence_of_dict))
    # While here we merge all dictionaries without caring about overlapping keys
    merged_dict = dict(collections.ChainMap(*sequence_of_dict))
    # And here we use the 'lambdas' to properly merge common keys
    for k in common_keys:
        values_with_common_key = [d[k] for d in sequence_of_dict]
        merged_dict[k] = functools.reduce(
            reduce_funcs.get(k, lambda x, y: x + y),
            values_with_common_key,
        )
    return merged_dict


class NamedBytesIO(io.BytesIO):
    """Buffer I/O with a name."""

    def __init__(self, content: bytes, name: str, mime_type: Optional[str] = None) -> None:
        """Constructor."""
        super().__init__(content)
        self._name = name
        self._mime_type = mime_type

    @property
    def name(self) -> str:
        """Property returning the file name."""
        return self._name

    @property
    def mime_type(self) -> Optional[str]:
        """Get the content type of the BytesIO, might be None."""
        return self._mime_type

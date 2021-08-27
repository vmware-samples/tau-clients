# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import collections
import datetime
import functools
import io
import ipaddress
import re
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Sized
from typing import Union
from urllib import parse

import pymisp


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

# Limit the number of objects to be created to avoid slowness, e.g., 1000+ domain-ip objects due to DGA.
MAX_SAME_TYPE_OBJ_CREATION = 30


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


class ResultParser:
    """This is a parser to extract *basic* information from a result dictionary."""

    def __init__(self, techniques_galaxy: Optional[Dict[str, str]] = None):
        """Constructor."""
        self.techniques_galaxy = techniques_galaxy or {}

    def parse(self, analysis_link: str, result: Dict[str, Any]) -> pymisp.MISPEvent:
        """
        Parse the analysis result into a MISP event.

        :param str analysis_link: the analysis link
        :param dict[str, any] result: the JSON returned by the analysis client.
        :rtype: pymisp.MISPEvent
        :return: a MISP event
        """
        misp_event = pymisp.MISPEvent()

        # Add analysis subject info
        if "url" in result["analysis_subject"]:
            o = pymisp.MISPObject("url")
            o.add_attribute("url", result["analysis_subject"]["url"])
        else:
            o = pymisp.MISPObject("file")
            o.add_attribute("md5", type="md5", value=result["analysis_subject"]["md5"])
            o.add_attribute("sha1", type="sha1", value=result["analysis_subject"]["sha1"])
            o.add_attribute("sha256", type="sha256", value=result["analysis_subject"]["sha256"])
            o.add_attribute(
                "mimetype",
                category="Payload delivery",
                type="mime-type",
                value=result["analysis_subject"]["mime_type"],
            )
        misp_event.add_object(o)

        # Add HTTP requests from url analyses
        network_dict = result.get("report", {}).get("analysis", {}).get("network", {})
        obj_count = 0
        for request in network_dict.get("requests", []):
            # Limit the number of objects to be created
            if obj_count > MAX_SAME_TYPE_OBJ_CREATION:
                break
            if not request["url"] or not request["ip"]:
                continue
            parsed_uri = parse.urlparse(request["url"])
            o = pymisp.MISPObject(name="http-request")
            o.add_attribute("host", parsed_uri.netloc)
            o.add_attribute("method", "GET")
            o.add_attribute("uri", request["url"])
            o.add_attribute("ip-dst", request["ip"])
            misp_event.add_object(o)
            obj_count += 1

        # Add network behaviors from files
        for subject in result.get("report", {}).get("analysis_subjects", []):

            # Add DNS requests
            obj_count = 0
            for dns_query in subject.get("dns_queries", []):
                if obj_count > MAX_SAME_TYPE_OBJ_CREATION:
                    break
                hostname = dns_query.get("hostname")
                # Skip if it is an IP address
                try:
                    if hostname == "wpad" or hostname == "localhost":
                        continue
                    # Invalid hostname, e.g., hostname: ZLKKJRPY or 2.2.0.10.in-addr.arpa.
                    if "." not in hostname or hostname[-1] == ".":
                        continue
                    _ = ipaddress.ip_address(hostname)
                    continue
                except ValueError:
                    pass

                o = pymisp.MISPObject(name="domain-ip")
                o.add_attribute("hostname", type="hostname", value=hostname)
                for ip in dns_query.get("results", []):
                    o.add_attribute("ip", type="ip-dst", value=ip)

                misp_event.add_object(o)
                obj_count += 1

            # Add HTTP conversations (as network connection and as http request)
            obj_count = 0
            for http_conversation in subject.get("http_conversations", []):
                if obj_count > MAX_SAME_TYPE_OBJ_CREATION:
                    break
                o = pymisp.MISPObject(name="network-connection")
                o.add_attribute("ip-src", http_conversation["src_ip"])
                o.add_attribute("ip-dst", http_conversation["dst_ip"])
                o.add_attribute("src-port", http_conversation["src_port"])
                o.add_attribute("dst-port", http_conversation["dst_port"])
                o.add_attribute("hostname-dst", http_conversation["dst_host"])
                o.add_attribute("layer3-protocol", "IP")
                o.add_attribute("layer4-protocol", "TCP")
                o.add_attribute("layer7-protocol", "HTTP")
                misp_event.add_object(o)

                method, path = http_conversation["url"].split(" ")[:2]
                if http_conversation["dst_port"] == 80:
                    uri = "http://{}{}".format(http_conversation["dst_host"], path)
                else:
                    uri = "http://{}:{}{}".format(
                        http_conversation["dst_host"], http_conversation["dst_port"], path
                    )
                o = pymisp.MISPObject(name="http-request")
                o.add_attribute("host", http_conversation["dst_host"])
                o.add_attribute("method", method)
                o.add_attribute("uri", uri)
                o.add_attribute("ip-dst", http_conversation["dst_ip"])
                misp_event.add_object(o)
                obj_count += 1

        # Add sandbox info like score and sandbox type
        o = pymisp.MISPObject(name="sandbox-report")
        sandbox_type = "saas" if is_task_link_hosted(analysis_link) else "on-premise"
        o.add_attribute("score", result["score"])
        o.add_attribute("sandbox-type", sandbox_type)
        o.add_attribute("{}-sandbox".format(sandbox_type), "vmware-nsx-defender")
        o.add_attribute("permalink", analysis_link)
        misp_event.add_object(o)

        # Add behaviors
        # Check if its not empty first, as at least one attribute has to be set for sb-signature object
        if result.get("malicious_activity", []):
            o = pymisp.MISPObject(name="sb-signature")
            o.add_attribute("software", "VMware NSX Defender")
            for activity in result.get("malicious_activity"):
                a = pymisp.MISPAttribute()
                a.from_dict(type="text", value=activity)
                o.add_attribute("signature", **a)
            misp_event.add_object(o)

        # Add mitre techniques
        for techniques in result.get("activity_to_mitre_techniques", {}).values():
            for technique in techniques:
                for misp_technique_id, misp_technique_name in self.techniques_galaxy.items():
                    if technique["id"].casefold() in misp_technique_id.casefold():
                        # If report details a sub-technique, trust the match
                        # Otherwise trust it only if the MISP technique is not a sub-technique
                        if "." in technique["id"] or "." not in misp_technique_id:
                            misp_event.add_tag(misp_technique_name)
                            break
        return misp_event

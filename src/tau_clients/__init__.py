"""
:Copyright:
    Copyright 2021 VMware, Inc.  All Rights Reserved.
"""
import re
from urllib import parse
from typing import Optional, Dict, Any


# All the domains that are used whenever NSX ATA is hosted
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

# These are constants representing NSX data centers
NSX_DEFENDER_DC_WESTUS = "west.us"
NSX_DEFENDER_DC_NLEMEA = "nl.emea"

NSX_DEFENDER_ANALYSIS_URLS = {
    NSX_DEFENDER_DC_WESTUS: "https://analysis.us.lastline.com",
    NSX_DEFENDER_DC_NLEMEA: "https://analysis.emea.lastline.com",
}

NSX_DEFENDER_PORTAL_URLS = {
    NSX_DEFENDER_DC_WESTUS: "https://user.us.lastline.com",
    NSX_DEFENDER_DC_NLEMEA: "https://user.emea.lastline.com",
}


def purge_none(d: Dict[Any, Any]) -> Dict[Any, Any]:
    """Purge None entries from a dictionary."""
    return {k: v for k, v in d.items() if v is not None}


def get_hash_type(hash_value: str) -> str:
    """Get the hash type."""
    if len(hash_value) == 32:
        return "md5"
    elif len(hash_value) == 40:
        return "sha1"
    elif len(hash_value) == 64:
        return "sha256"
    else:
        return None


def get_task_link(uuid: str, analysis_url: Optional[str]=None, portal_url: Optional[str]=None) -> str:
    """
    Get the task link given the task uuid and at least one API url.

    :param str uuid: the task uuid
    :param str|None analysis_url: the URL to the analysis API endpoint
    :param str|None portal_url: the URL to the portal API endpoint
    :rtype: str
    :return: the task link
    :raises ValueError: if not enough parameters have been provided
    """
    if not analysis_url and not portal_url:
        raise ValueError("Neither analysis URL or portal URL have been specified")
    if analysis_url:
        portal_url = "{}/papi".format(analysis_url.replace("analysis.", "user."))
    portal_url_path = "../portal#/analyst/task/{}/overview".format(uuid)
    return parse.urljoin(portal_url, portal_url_path)


def get_portal_url_from_task_link(task_link: str) -> str:
    """
    Return the portal API url related to the provided task link.

    :param str task_link: a link
    :rtype: str
    :return: the portal API url
    """
    parsed_uri = parse.urlparse(task_link)
    return "{uri.scheme}://{uri.netloc}/papi".format(uri=parsed_uri)


def get_uuid_from_task_link(task_link: str) -> str:
    """
    Return the uuid from a task link.

    :param str task_link: a link
    :rtype: str
    :return: the uuid
    :raises ValueError: if the link contains not task uuid
    """
    try:
        return re.findall("[a-fA-F0-9]{32}", task_link)[0]
    except IndexError:
        raise ValueError(  # pylint: disable=W0707
            "Link does not contain a valid task uuid"
        )


def is_task_hosted(task_link: str) -> bool:
    """
    Return whether the portal link is pointing to a hosted submission.

    :param str task_link: a link
    :rtype: boolean
    :return: whether the link points to a hosted analysis
    """
    for domain in NSX_DEFENDER_HOSTED_DOMAINS:
        if domain in task_link:
            return True
    return False

# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import ipaddress
from typing import Any
from typing import Dict
from typing import Optional
from urllib import parse

import pymisp
import tau_clients


# Limit the number of objects to be created to avoid slowness, e.g., 1000+ domain-ip objects due to DGA.
MAX_SAME_TYPE_OBJ_CREATION = 30


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
        sandbox_type = "saas" if tau_clients.is_task_link_hosted(analysis_link) else "on-premise"
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

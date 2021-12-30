#!/usr/bin/env python
# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import unittest

import ddt
import tau_clients

TEST_QUERY_HASH_TASK = {
    "expires": "2021-01-25 21:31:15",
    "file_sha1": "00452a9ff639b55c5d979c4ed655ddfd4cf8d166",
    "file_md5": "d26d895d99a7381b9c41fbde5388b7f3",
    "task_uuid": "f352d739569c00201dc3dee713dadf77",
    "score": 70,
    "file_sha256": "e230f33416157afbb22c6db78c7a4aec057e45a709ce3a36d8dc77291d70dd45",
}


@ddt.ddt
class ClientTestCase(unittest.TestCase):
    """Test some basic utilities."""

    @ddt.data(
        (
            {"tasks": [{"a": 1}], "file_found": 1},
            {"files_found": 0},
            {"files_found": 0, "tasks": [{"a": 1}], "file_found": 1},
        ),
        (
            {"file_found": 2},
            {"tasks": [TEST_QUERY_HASH_TASK], "files_found": 1},
            {"files_found": 1, "tasks": [TEST_QUERY_HASH_TASK], "file_found": 2},
        ),
    )
    def test_merge_dicts(self, args):
        """Test merging dictionaries."""
        d1, d2, expected_result = args
        result = tau_clients.merge_dicts([d1, d2])
        self.assertEqual(result, expected_result)

    @ddt.data(
        (
            "https://user.lastline.com/portal#/network/event/3086636740/983923901/"
            "1264665?customer=partner-demo-account@lastline.com",
            tau_clients.EventDescriptor(
                event_id="1264665",
                event_time=None,
                obfuscated_key_id="3086636740",
                obfuscated_subkey_id="983923901",
                data_center=tau_clients.NSX_DEFENDER_DC_WESTUS,
            ),
        ),
        (
            "https://user.emea.lastline.com/portal#/network/event/3086636740/983923901/"
            "1264665?customer=partner-demo-account@lastline.com",
            tau_clients.EventDescriptor(
                event_id="1264665",
                event_time=None,
                obfuscated_key_id="3086636740",
                obfuscated_subkey_id="983923901",
                data_center=tau_clients.NSX_DEFENDER_DC_NLEMEA,
            ),
        ),
        (
            "https://user.us.lastline.com/portal#/network/event/3086636740/983923901/"
            "1264665?customer=partner-demo-account@lastline.com",
            tau_clients.EventDescriptor(
                event_id="1264665",
                event_time=None,
                obfuscated_key_id="3086636740",
                obfuscated_subkey_id="983923901",
                data_center=tau_clients.NSX_DEFENDER_DC_WESTUS,
            ),
        ),
        (
            "https://user.lastline.com/portal#/network/event/3086636740/983923901/1264665",
            tau_clients.EventDescriptor(
                event_id="1264665",
                event_time=None,
                obfuscated_key_id="3086636740",
                obfuscated_subkey_id="983923901",
                data_center=tau_clients.NSX_DEFENDER_DC_WESTUS,
            ),
        ),
        (
            "https://user.lastline.com/portal#/network/event/3086636740/983923901/1264665?",
            tau_clients.EventDescriptor(
                event_id="1264665",
                event_time=None,
                obfuscated_key_id="3086636740",
                obfuscated_subkey_id="983923901",
                data_center=tau_clients.NSX_DEFENDER_DC_WESTUS,
            ),
        ),
        (
            "https://user.lastline.com/portal#/network/event/3086636740/983923901/"
            "1264665?event_time=2021-12-30",
            tau_clients.EventDescriptor(
                event_id="1264665",
                event_time="2021-12-30",
                obfuscated_key_id="3086636740",
                obfuscated_subkey_id="983923901",
                data_center=tau_clients.NSX_DEFENDER_DC_WESTUS,
            ),
        ),
        (
            "https://user.lastline.com/portal#/network/event/3086636740/983923901/"
            "1264665?customer=partner-demo-account@lastline.com&event_time=2021-12-30",
            tau_clients.EventDescriptor(
                event_id="1264665",
                event_time="2021-12-30",
                obfuscated_key_id="3086636740",
                obfuscated_subkey_id="983923901",
                data_center=tau_clients.NSX_DEFENDER_DC_WESTUS,
            ),
        ),
        (
            "https://user.last.com/portal#/network/event/3086636740/983923901/"
            "1264665?event_time=2021-12-30",
            None,
        ),
        (
            "https://user.lastline.com/portal#/network/event/3086636740/"
            "1264665?event_time=2021-12-30",
            None,
        ),
    )
    def test_parse_portal_link(self, args):
        """Test parsing portal links."""
        portal_link, expected_event_descriptor = args
        event_descriptor = tau_clients.parse_portal_link(portal_link)
        self.assertEqual(event_descriptor, expected_event_descriptor)


if __name__ == "__main__":
    unittest.main()

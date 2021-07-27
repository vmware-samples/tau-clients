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


if __name__ == "__main__":
    unittest.main()

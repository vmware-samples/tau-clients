# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import functools
import json
import textwrap
import unittest
from typing import List
from typing import Tuple

import ddt
import mock
from tau_clients import decoders
from tau_clients import exceptions

TEST_SHA1_1 = "a" * 40
TEST_SHA1_2 = "b" * 40
TEST_UUID_1 = "2f945319183a004000f0486eb8aab782"


@ddt.ddt
class DecoderTestCase(unittest.TestCase):
    """Test the decoder."""

    @staticmethod
    def _side_effect_walk(
        path: str,
        existing_path: str,
        existing_files: List[str],
    ) -> List[Tuple[str, None, List[str]]]:
        """
        Side-effect returning a list of existing file if the path matches the existing path.

        :param str path: the path
        :param str existing_path: the path flagged as existing
        :param list[str] existing_files: the existing files to be returned
        :rtype: tuple(str, None, list[str])
        :return: the mocked walk
        """
        if path in existing_path:
            return [(path, None, existing_files)]
        else:
            return []

    @staticmethod
    def _side_effect_exists(path: str, existing_paths: List[str]) -> bool:
        """
        Side-effect returning whether something exists.

        :param str path: the path
        :param str existing_paths: the list of existing paths
        :rtype: bool
        :return: the mocked exist
        """
        if path in existing_paths:
            return True
        else:
            return False

    @ddt.data(
        ([TEST_SHA1_1, TEST_SHA1_2], decoders.InputType.FILE_HASH),
        ([TEST_UUID_1], decoders.InputType.TASK_UUID),
    )
    def test_decode_input(self, args):
        """Test the decoder when parsing command line."""
        arguments, expected_type = args
        decoder = decoders.InputTypeDecoder()
        input_bits, input_type = decoder.decode(
            input_type=decoders.InputType.NULL,
            arguments=arguments,
            inspect_content=False,
        )
        self.assertEqual(input_type, expected_type)
        self.assertEqual(input_bits, arguments)
        # try again with no hint, we should get the same results
        input_bits, input_type = decoder.decode(
            input_type=expected_type,
            arguments=arguments,
            inspect_content=False,
        )
        self.assertEqual(input_type, expected_type)
        self.assertEqual(input_bits, arguments)

    @ddt.data(
        ([TEST_SHA1_1, TEST_SHA1_2], decoders.InputType.FILE_HASH),
        ([TEST_UUID_1], decoders.InputType.TASK_UUID),
    )
    def test_decode_input__inspect(self, args):
        """Test the decoder when parsing command line and we say to inspect files (weird)."""
        arguments, expected_type = args
        decoder = decoders.InputTypeDecoder()
        input_bits, input_type = decoder.decode(
            input_type=decoders.InputType.NULL,
            arguments=arguments,
            inspect_content=True,
        )
        self.assertEqual(input_type, expected_type)
        self.assertEqual(input_bits, arguments)
        # try again with no hint, we should get the same results
        input_bits, input_type = decoder.decode(
            input_type=expected_type,
            arguments=arguments,
            inspect_content=True,
        )
        self.assertEqual(input_type, expected_type)
        self.assertEqual(input_bits, arguments)

    def test_decode_input__multiple(self):
        """Test the decoder when parsing files but the arguments have different types."""
        decoder = decoders.InputTypeDecoder()
        with mock.patch("os.path.isfile") as mock_file:
            mock_file.side_effect = functools.partial(
                self._side_effect_exists,
                existing_paths=["path/to/open"],
            )
            with self.assertRaisesRegexp(exceptions.InputTypeException, "Could not choose"):
                _, _ = decoder.decode(
                    input_type=decoders.InputType.NULL,
                    arguments=["path/to/open", TEST_SHA1_1],
                    inspect_content=False,
                )
            # try again with no hint and we should see no difference
            with self.assertRaisesRegexp(exceptions.InputTypeException, "Could not choose"):
                _, _ = decoder.decode(
                    input_type=decoders.InputType.FILE_HASH,
                    arguments=["path/to/open", TEST_SHA1_1],
                    inspect_content=False,
                )

    @ddt.data(
        # JSON
        (json.dumps([TEST_SHA1_1]), [TEST_SHA1_1]),
        (json.dumps([{"sha1": TEST_SHA1_1}]), [TEST_SHA1_1]),
        (json.dumps([{"file_sha1": TEST_SHA1_1}]), [TEST_SHA1_1]),
        (json.dumps([{"file_md5": TEST_SHA1_2, "file_sha1": TEST_SHA1_1}]), [TEST_SHA1_1]),
        (json.dumps([{"file_md5": TEST_SHA1_1}]), [TEST_SHA1_1]),
        # CSV
        (
            textwrap.dedent(
                f"""
            label1,file_sha1
            data,{TEST_SHA1_1}
            """
            ).strip(),
            [TEST_SHA1_1],
        ),
        # PLAIN TEXT
        (
            textwrap.dedent(
                f"""
            {TEST_SHA1_1}
            {TEST_SHA1_2}
            """
            ).strip(),
            [TEST_SHA1_1, TEST_SHA1_2],
        ),
    )
    def test_decode_input__file(self, args):
        """Test the decoder when parsing files."""
        test_data, expected_result = args
        decoder = decoders.InputTypeDecoder()
        with mock.patch("builtins.open", mock.mock_open(read_data=test_data)) as mock_file:
            input_bits, input_type = decoder.decode(
                input_type=decoders.InputType.FILE,
                arguments=["path/to/open"],
                inspect_content=True,
            )
            mock_file.assert_called_with("path/to/open", "r")
            self.assertEqual(input_type, decoders.InputType.FILE_HASH)
            self.assertEqual(input_bits, expected_result)
            # try again with no hint and the only difference is that we test a file for existence
            with mock.patch("os.path.isfile") as mock_file_2:

                def side_effect(filename):
                    if filename == "path/to/open":
                        return True
                    else:
                        return False

                mock_file_2.side_effect = side_effect
                input_bits, input_type = decoder.decode(
                    input_type=decoders.InputType.NULL,
                    arguments=["path/to/open"],
                    inspect_content=True,
                )
                mock_file.assert_called_with("path/to/open", "r")
                self.assertEqual(input_type, decoders.InputType.FILE_HASH)
                self.assertEqual(input_bits, expected_result)

    def test_decode_input__file__no_inspect(self):
        """Test the decoder when parsing files but we give up inspecting."""
        decoder = decoders.InputTypeDecoder()
        with mock.patch("os.path.isfile") as mock_file:
            mock_file.side_effect = functools.partial(
                self._side_effect_exists,
                existing_paths=["path/to/open"],
            )
            input_bits, input_type = decoder.decode(
                input_type=decoders.InputType.FILE,
                arguments=["path/to/open"],
                inspect_content=False,
            )
            self.assertEqual(input_type, decoders.InputType.FILE)
            self.assertEqual(input_bits, ["path/to/open"])
            # try again with no hint and we should see no difference
            input_bits, input_type = decoder.decode(
                input_type=decoders.InputType.NULL,
                arguments=["path/to/open"],
                inspect_content=False,
            )
            self.assertEqual(input_type, decoders.InputType.FILE)
            self.assertEqual(input_bits, ["path/to/open"])

    def test_decode_input__directory(self):
        """Test the decoder when parsing a directory."""
        decoder = decoders.InputTypeDecoder()
        with mock.patch("os.path.isdir") as mock_dir:
            with mock.patch("os.walk") as mock_walk:
                with mock.patch("os.path.isfile") as mock_file:
                    mock_dir.side_effect = functools.partial(
                        self._side_effect_exists, existing_paths=["path/to/list"]
                    )
                    mock_walk.side_effect = functools.partial(
                        self._side_effect_walk,
                        existing_path="path/to/list",
                        existing_files=["a", "b"],
                    )
                    mock_file.side_effect = functools.partial(
                        self._side_effect_exists,
                        existing_paths=["path/to/list/a", "path/to/list/b"],
                    )
                    input_bits, input_type = decoder.decode(
                        input_type=decoders.InputType.DIRECTORY,
                        arguments=["path/to/list"],
                        inspect_content=False,
                    )
                    self.assertEqual(input_type, decoders.InputType.FILE)
                    self.assertEqual(input_bits, ["path/to/list/a", "path/to/list/b"])
                    # try again with no hint but we should see no difference
                    input_bits, input_type = decoder.decode(
                        input_type=decoders.InputType.NULL,
                        arguments=["path/to/list"],
                        inspect_content=False,
                    )
                    self.assertEqual(input_type, decoders.InputType.FILE)
                    self.assertEqual(input_bits, ["path/to/list/a", "path/to/list/b"])

    def test_decode_input__directory__empty(self):
        """Test the decoder when parsing an empty directory."""
        decoder = decoders.InputTypeDecoder()
        with mock.patch("os.path.isdir") as mock_dir:
            with mock.patch("os.walk") as mock_walk:
                mock_dir.side_effect = functools.partial(
                    self._side_effect_exists, existing_paths=["path/to/list"]
                )
                mock_walk.side_effect = functools.partial(
                    self._side_effect_walk,
                    existing_path="path/to/list",
                    existing_files=[],
                )
                with self.assertRaisesRegexp(exceptions.InputTypeException, "Could not infer"):
                    _, _ = decoder.decode(
                        input_type=decoders.InputType.DIRECTORY,
                        arguments=["path/to/list"],
                        inspect_content=False,
                    )
                # try again with no hint but we should see no difference
                with self.assertRaisesRegexp(exceptions.InputTypeException, "Could not infer"):
                    _, _ = decoder.decode(
                        input_type=decoders.InputType.NULL,
                        arguments=["path/to/list"],
                        inspect_content=False,
                    )

    @ddt.data(
        # JSON
        (json.dumps([]), []),
        (json.dumps([{"file_md4": TEST_SHA1_1}]), []),
        # CSV
        (
            textwrap.dedent(
                """
            label1,file_sha1
            """
            ).strip(),
            [],
        ),
        (
            textwrap.dedent(
                """
            label1,file_md5
            """
            ).strip(),
            [],
        ),
        # PLAIN TEXT
        (
            textwrap.dedent(
                """
            test1
            test2
            """
            ).strip(),
            [],
        ),
    )
    def test_decode_input__file__empty(self, args):
        """Test the decoder when parsing empty files."""
        test_data, expected_result = args
        decoder = decoders.InputTypeDecoder()
        with mock.patch("builtins.open", mock.mock_open(read_data=test_data)) as _:
            with self.assertRaisesRegexp(exceptions.InputTypeException, "Could not decode"):
                _, _ = decoder.decode(
                    input_type=decoders.InputType.FILE,
                    arguments=["path/to/open"],
                    inspect_content=True,
                )
            # try again with no hint but we should see no difference
            with self.assertRaisesRegexp(exceptions.InputTypeException, "Could not infer"):
                _, _ = decoder.decode(
                    input_type=decoders.InputType.NULL,
                    arguments=["path/to/open"],
                    inspect_content=True,
                )

    def test_decode_input__file__no_inspect__empty(self):
        """Test the decoder when parsing empty files and give up inspecting."""
        decoder = decoders.InputTypeDecoder()
        with mock.patch("os.path.isfile") as mock_file:
            mock_file.side_effect = functools.partial(
                self._side_effect_exists,
                existing_paths=[],
            )
            with self.assertRaisesRegexp(exceptions.InputTypeException, "Could not infer"):
                _, _ = decoder.decode(
                    input_type=decoders.InputType.FILE,
                    arguments=["path/to/open"],
                    inspect_content=False,
                )
            # try again with no hint but we should see no difference
            with self.assertRaisesRegexp(exceptions.InputTypeException, "Could not infer"):
                _, _ = decoder.decode(
                    input_type=decoders.InputType.NULL,
                    arguments=["path/to/open"],
                    inspect_content=False,
                )

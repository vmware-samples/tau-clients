# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import argparse
import csv
import enum
import functools
import itertools
import json
import os
from typing import Collection
from typing import List
from typing import Optional
from typing import Tuple

import tau_clients
from tau_clients import exceptions


class InputType(enum.Enum):
    """Enumeration specifying all different input types."""

    DIRECTORY = "directory"
    FILE = "file"
    FILE_HASH = "file-hash"
    TASK_UUID = "task-uuid"
    NULL = "null"

    @classmethod
    def _missing_(cls, value: Optional[str]) -> "InputType":
        """Return a sentinel value if the value is missing (py39 does not support 'None')."""
        return InputType.NULL

    def __bool__(self):
        """Treat sentinel values as actual 'None'."""
        return self != InputType.NULL


class InputTypeDecoder:
    """Class to decode the input provided by the user."""

    # this is a list because we need it sorted by priority
    SUPPORTED_FIELD_NAMES = [
        "sha256",
        "file_sha256",
        "sha1",
        "file_sha1",
        "md5",
        "file_md5",
        "task_uuid",
    ]

    @staticmethod
    def add_arguments_to_parser(
        parser: argparse.ArgumentParser, choices: List[InputType]
    ) -> None:
        """
        Add to the parser enough arguments to satisfy the provided options.

        :param ArgumentParser parser: the parser
        :param listr[InputType] choices: the valid option
        """
        choices_vals = [getattr(x, "value") for x in choices if x]
        choices_str = ",".join(choices_vals)
        parser.add_argument(
            "-u",
            "--input-type",
            dest="input_type",
            choices=choices_vals,
            default=InputType.NULL,
            help=f"what the input represents ({choices_str}) defaults to auto-detect",
        )
        parser.add_argument(
            "input_bits",
            metavar="input_bits",
            nargs="+",
            help=f"any {choices_str}",
        )

    @staticmethod
    def _find_field_name(field_names: Collection[str]) -> Optional[str]:  # pylint: disable=E1136
        """
        Return a valid field name present in the list of candidates.

        :param collection[str] field_names: a collection of field names
        :rtype: the identified field name
        :return: the preferred field name
        """
        for field_name in InputTypeDecoder.SUPPORTED_FIELD_NAMES:
            if field_name in field_names:
                return field_name
        return None

    @staticmethod
    def _parse_csv_file(file_path: str, scan_keys: bool = False) -> List[str]:
        """
        Parse a CSV file and return values from field names in 'SUPPORTED_FIELD_NAMES'.

        Note: if 'scan_keys' is set then this method will cannibalize the plain text parser,
            which might what we want or NOT, so use it as a last resort.

        :param str file_path: the file path
        :param bool scan_keys: whether to scan also keys as last resort
        :rtype: list[str]
        :return: a list of hash-like values
        :raises FileParseError: for any error reading the file
        """
        hashes = set([])
        try:
            with open(file_path, "r") as csv_file:  # pylint:disable=W1514
                reader = csv.DictReader(csv_file)
                field_name = InputTypeDecoder._find_field_name(reader.fieldnames)
                for row in reader:
                    if scan_keys:
                        for raw_value in row.values():
                            try:
                                InputTypeDecoder._decode_hash(raw_value)
                            except exceptions.DecodeError:
                                pass
                            else:
                                hashes.add(raw_value)
                    else:
                        file_hash = row.get(field_name)
                        if file_hash:
                            hashes.add(file_hash)
        except (IOError, csv.Error) as err:
            raise exceptions.FileParseError from err
        return sorted(hashes)

    @staticmethod
    def _parse_json_file(file_path: str) -> List[str]:
        """
        Parse a JSON file and return values from field names in 'SUPPORTED_FIELD_NAMES'.

        :param str file_path: the file path
        :rtype: list[str]
        :return: a list of hash-like values
        :raises FileParseError: for any error reading the file
        """
        hashes = set([])
        try:
            with open(file_path, "r") as json_file:  # pylint:disable=W1514
                json_data = json.load(json_file)
        except (IOError, json.JSONDecodeError) as err:
            raise exceptions.FileParseError from err
        field_name = None
        # We support two data types
        for element in json_data:
            # ... a list of dict elements
            if isinstance(element, dict):
                if not field_name:
                    field_name = InputTypeDecoder._find_field_name(element.keys())
                file_hash = element.get(field_name)
                if file_hash:
                    hashes.add(file_hash)
            # ... or a list of hash-like strings
            elif isinstance(element, str):
                try:
                    InputTypeDecoder._decode_hash(element)
                except exceptions.DecodeError:
                    pass
                else:
                    hashes.add(element)
        return sorted(hashes)

    @staticmethod
    def _parse_text_file(file_path: str) -> List[str]:
        """
        Parse a plain text file and return hash-like strings.

        :param str file_path: the file path
        :rtype: list[str]
        :return: a list of hash-like values
        :raises FileParseError: for any error reading the file
        """
        hashes = set([])
        try:
            with open(file_path, "r") as data_file:  # pylint:disable=W1514
                data = data_file.readlines()
        except IOError as ioe:
            raise exceptions.FileParseError from ioe
        for line in data:
            line = line.strip()
            try:
                InputTypeDecoder._decode_hash(line)
            except exceptions.DecodeError:
                pass
            else:
                hashes.add(line)
        if not hashes:
            raise exceptions.FileParseError("Empty data")
        return sorted(hashes)

    @staticmethod
    def _parse_directory(file_path: str) -> List[str]:
        """
        Parse a directory and return a list of files.

        :param str file_path: the file path
        :rtype: list[str]
        :return: a list of file paths
        """
        return sorted(
            [os.path.join(dp, f) for dp, _, filenames in os.walk(file_path) for f in filenames]
        )

    @staticmethod
    def _decode_hash(argument: str) -> InputType:
        """
        Decode the input of a hash-like string.

        :param str argument: the input
        :rtype: InputType
        :return: the decoded input type
        :raises DecodeError: if the argument is not hash-like
        """
        hash_type = tau_clients.get_hash_type(argument)
        if not hash_type:
            raise exceptions.DecodeError("Not possible to parse the string")
        if tau_clients.is_likely_task_uuid(argument):
            return InputType.TASK_UUID
        else:
            return InputType.FILE_HASH

    @staticmethod
    def _decode_string(argument: str) -> InputType:
        """
        Decode the input of a string, possible a file path.

        :param str argument: the input
        :rtype: InputType
        :return: the decoded input type
        :raises DecodeError: if the argument is not file or hash-like
        """
        if os.path.isfile(argument):
            return InputType.FILE
        elif os.path.isdir(argument):
            return InputType.DIRECTORY
        else:
            return InputTypeDecoder._decode_hash(argument)

    def _decode_input_type(self, arguments: List[str]) -> InputType:
        """
        Decode the input of a list of strings.

        :param list[str] arguments: the input list
        :rtype: InputType
        :return: the decoded input type
        :raises InputTypeException: if the decoding failed
        """
        input_types = set([])
        for argument in arguments:
            try:
                input_type = self._decode_string(argument)
                input_types.add(input_type)
            except exceptions.DecodeError:
                pass
        if len(input_types) > 1:
            raise exceptions.InputTypeException("Could not choose input type")
        try:
            return input_types.pop()
        except KeyError as ke:
            raise exceptions.InputTypeException("Could not infer input type") from ke

    def decode(
        self,
        arguments: List[str],
        input_type: InputType = InputType.NULL,
        inspect_content: bool = True,
    ) -> Tuple[List[str], InputType]:
        """
        Decode the input received by the user and return a list of decoded inputs and types.

        :param list[str] arguments: the input list
        :param InputType input_type: hint about the input type
        :param bool inspect_content: whether the input type should be content-inspected
        :rtype: tuple[list[str], InputType]
        :return: a tuple with the parsed input type and a list of decoded input bits
        :raises InputTypeException: when the input can not be decoded
        """
        # If we are given no type (or it is a file with no inspection), infer it!
        if not input_type or (input_type is InputType.FILE and not inspect_content):
            input_type = self._decode_input_type(arguments)

        # If it is a directory let us walk it
        if input_type is InputType.DIRECTORY:
            arguments = sorted(itertools.chain(*[self._parse_directory(x) for x in arguments]))
            input_type = InputType.FILE

        # If we are not inspecting a file, return the current data
        if not (input_type is InputType.FILE and inspect_content):
            # but do a further decode round in case this is a hinted 'input_type'
            input_type = self._decode_input_type(arguments)
            return arguments, input_type

        # ... at this point we can only try to parse files
        for parse_function in [
            self._parse_json_file,
            self._parse_csv_file,
            self._parse_text_file,
            functools.partial(self._parse_csv_file, scan_keys=True),
        ]:
            try:
                new_arguments = []
                for argument in arguments:
                    new_arguments.extend(parse_function(argument))
                if new_arguments:
                    return self.decode(new_arguments, input_type=InputType.NULL)
            except exceptions.FileParseError:
                continue
        raise exceptions.InputTypeException("Could not decode any data")

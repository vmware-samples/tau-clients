# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2


class InvalidArgument(Exception):
    """Error raised invalid."""


class CommunicationError(Exception):
    """Exception raised in case of timeouts or other network problem."""


class Error(Exception):
    """Generic server error."""


class ApiError(Error):
    """Server error with a message and an error code."""

    def __init__(self, error_msg, error_code=None):
        super(ApiError, self).__init__(error_msg, error_code)
        self.error_msg = error_msg
        self.error_code = error_code

    def __str__(self):
        if self.error_code is None:
            error_code = ""
        else:
            error_code = " ({})".format(self.error_code)
        return "{}{}".format(self.error_msg or "", error_code)

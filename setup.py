#!/usr/bin/env python
# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2
"""
See https://stackoverflow.com/questions/62983756/what-is-pyproject-toml-file-for
"""
import setuptools

if __name__ == "__main__":
    setuptools.setup(
        install_requires=[
            "pymisp==2.4.143",
        ]
    )

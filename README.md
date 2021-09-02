![GitHub tag (latest SemVer)](https://img.shields.io/github/tag/vmware-samples/tau-clients)
![GitHub](https://img.shields.io/pypi/l/tau-clients)
![GitHub issues](https://img.shields.io/github/issues/vmware-samples/tau-clients)

# Threat Analysis Unit Clients

## Overview

Threat Analysis Unit Clients (shortened as `tau-clients`) is a set of clients that can be used
to programmatically interface with various VMware products and/or external services or
resources, with a focus on threat analysis and intelligence collection.

## Try it out

### Notes

* A client might require a specific and valid license; for example, both `PortalClient` and
  `AnalysisClient` require a valid NSX Defender license.
* Support and bug reports are exclusively handled via GitHub.
* A fully supported commercial implementation of `AnalysisClient` is available here:
  https://analysis.lastline.com/analysis/api-docs/html/analysis_client.html

### Build & Run

This package can be installed via pip, just run `pip install tau-clients` or `pip install -e .`

To run a simple example just create a valid configuration file using `data/tau_clients.ini.template`.
```python
import configparser
from tau_clients import nsx_defender

conf = configparser.ConfigParser()
conf.read("./data/tau_clients.ini")
portal_client = nsx_defender.PortalClient.from_conf(conf, "portal")
result = portal_client.get_tasks_from_knowledgebase(
    query_string="file_sha1: 'ba81b98f00168b86578e5f5de93d26ed83769432'",
)
```

### Scripts

This package includes the following console scripts ready to be used (assuming a valid
configuration file is also provided):

* `download_artifacts.py`: download all the available analysis artifacts given a file has or
  task uuid.
* `submit_samples.py`: submit the samples contained in the provided directory; if a file hash is
  provided download the sample from VirusTotal.

## Contributing

The tau-clients project team welcomes contributions from the community. Before you start working with tau-clients, please
read our [Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions to this repository must be
signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on
as an open-source patch. For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## Development

Create the virtual env:

`python3 -m venv venv`

Activate the virtual env:

`source ./venv/bin/activate`

Install `tox`:

`pip install tox`

Run tests:

`tox`

Due to a bug in `tox` if you update the dependencies in `setup.cfg` the environments will not be
re-created, leading to errors when running the tests
(see https://github.com/tox-dev/tox/issues/93).
As workaround, pass the `--recreate` flag after updating the dependencies.

Before committing, install the package in dev mode (needed by `pylint`):

`pip install -e .`

Install `pylint` and `pre-commit`:

`pip install pylint pre-commit`

Install the hook:

`pre-commit install`

If you want to run pre-commit on all files use the following command:

`pre-commit run --all-files`

## License
[BSD 2-Clause](https://spdx.org/licenses/BSD-2-Clause.html)

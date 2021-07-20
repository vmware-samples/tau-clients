# TAU Clients

Tau-Clients is a set of clients that can be used to programmatically interface with various
VMware products and/or external services or resources, with a focus on threat analysis and
intelligence collection.

## Development

Create the virtual env:

`python3 -m venv venv`

Activate the virtual env:

`source ./venv/bin/activate`

Install `tox`:

`pip install tox`

Run tests:

`tox`

Install the package in dev mode (needed by `pylint`):

`pip install -e .`

Install `pylint` and `pre-commit`:

`pip install pylint pre-commit`

Install the hook:

`pre-commit install`

Run pre-commit on all files (optional)

`pre-commit run --all-files`

## Notes

Due to a bug in `tox` if you update the dependencies in `setup.cfg` the environments will not be
re-created, leading to errors when running the tests
(see https://github.com/tox-dev/tox/issues/93).
As workaround, pass the `--recreate` flag after updating the dependencies.

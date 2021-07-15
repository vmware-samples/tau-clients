# Tina Client

See project https://<> for examples.

## Development

Create the virtual env:

`python3 -m venv venv`

Activate the virtual env:

`source ./venv/bin/activate`

Install tox:

`pip install tox`

Run tests:

`tox`

Install the package in dev mode (needed by pylint):

`pip install -e .`

Install pylint and pre-commit:

`pip install pylint pre-commit`

Install the hook

`pre-commit install`

Run pre-commit on all files (optional)

`pre-commit run --all-files`

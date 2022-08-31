# About

## How to run

Prepare venv.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip>=21.3
pip install -r requirements-dev.txt
pip install .
# or "editable" install
# SETUPTOOLS_ENABLE_FEATURES="legacy-editable" pip install -e .
```

To run the code you would need a Keycloak instance, you can run one locally or
in the [cloud](https://developers.redhat.com/developer-sandbox/get-started).

```bash
source .venv/bin/activate
export SSO_API_URL='https://sso-cvaldezr-stage.apps.sandbox.x8i5.p1.openshiftapps.com/'
export SSO_API_USERNAME=admin
export SSO_API_PASSWORD=admin
export SSO_TOKEN_FILENAME=test-token.json

kcfetcher_save_token
kcfetcher
```

## Development

Run tests.

```bash
# all python versions
tox
# or only specific python version
tox -e py38
# or integration tests only
pytest tests/integration
# or specific test only
tox -e py38 -- tests/integration/test_ping.py::TestOK::test_ok
pytest -v tests/integration/test_ping.py::TestOK::test_ok
```

Build package.

```bash
pip install --upgrade build twine
python3 -m build
# twine upload --repository testpypi dist/*
```

# About

## How to run

Prepare venv.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements-dev.txt
pip install .
# or "editable" install
# SETUPTOOLS_ENABLE_FEATURES="legacy-editable" pip install -e .
```

If needed, load test data in test container:

```shell
source .venv/bin/activate
export SSO_API_URL='https://172.17.0.2:8443/'
export SSO_API_USERNAME=admin
export SSO_API_PASSWORD=admin
./.github/inject_data.py
```

Run code

```bash
source .venv/bin/activate
export SSO_API_URL='https://172.17.0.2:8443/'
export SSO_API_USERNAME=admin
export SSO_API_PASSWORD=admin
kcfetcher
```

## Development

For integration tests you need to put credentials into `env.env` file in the top-level directory.
Use `env.env.sample` as template.

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

## Setup Keycloak server for testing

```shell
docker run -it -p 8080:80 -p 8433:443 -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=admin quay.io/keycloak/keycloak:15.0.2 -b 0.0.0.0
```

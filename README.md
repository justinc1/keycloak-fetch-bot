# About

## How to run

Prepare venv.

```
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip>=21.3
pip install -r requirements.txt 
pip install -e .
```

Run code

```
source .venv/bin/activate
export SSO_API_URL='https://sso-cvaldezr-stage.apps.sandbox.x8i5.p1.openshiftapps.com/'
export SSO_API_USERNAME=admin
export SSO_API_PASSWORD=admin
kcfetcher
```

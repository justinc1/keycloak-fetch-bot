#!/usr/bin/env python

import logging
import os

from kcfetcher.fetch import FetchFactory, RealmFetch
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)d %(levelname)-8s %(name)s [%(filename)s:%(lineno)d]: %(message)s",
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger(__name__)


def run(output_dir):
    remove_folder(output_dir)
    make_folder(output_dir)

    # Credentials
    server = os.environ.get('SSO_API_URL', 'https://sso-cvaldezr-stage.apps.sandbox.x8i5.p1.openshiftapps.com/')
    user = os.environ.get('SSO_API_USERNAME', 'admin')
    password = os.environ.get('SSO_API_PASSWORD', 'admin')
    if os.environ.get("KEYCLOAK_API_CA_BUNDLE") == "":
        # disable annoying warning
        import requests
        requests.packages.urllib3.disable_warnings()

    kc = login(server, user, password)
    realms_api = kc.admin()
    logger.info(f"Server profile={kc.server_info.profile_name} version={kc.server_info.version}")

    #  ['keycloak_resource', 'unique identifier']
    resources = [
        ['clients', 'clientId'],
        ['roles', 'name'],
        ['identity-provider', 'alias'],
        ['user-federations', 'name'],
        ['components', 'name'],
        ['authentication', 'alias'],
        ['authentication/required-actions', 'alias'],
        ['groups', 'name'],
        ['client-scopes', 'name'],
        # Do not save users, we do not need them, and it takes time.
        # ['users', 'username'],
    ]

    store = Store(path=output_dir)
    realm_fetcher = RealmFetch(kc)
    for realm in realms_api.all():
        realm_name = realm['realm']
        store.add_child(realm_name)  # outd/<realm>

        realm_fetcher.fetch_one(store, realm)
        for resource in resources:
            fetch_keycloak_objects = FetchFactory().create(resource, kc, realm_name)
            store.add_child(resource[0])
            fetch_keycloak_objects.fetch(store)
            store.remove_last_child()

        store.remove_last_child()  # outd/<realm>


def main_cli():
    output_dir = "output/keycloak"
    run(output_dir)


if __name__ == '__main__':
    run("output/keycloak")

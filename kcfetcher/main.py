#!/usr/bin/env python

import os

from kcfetcher.fetch import FetchFactory
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login


def run(output_dir="keycloak"):
    remove_folder(output_dir)
    make_folder(output_dir)

    # Credentials
    server = os.environ.get('SSO_API_URL', 'https://sso-cvaldezr-stage.apps.sandbox.x8i5.p1.openshiftapps.com/')
    user = os.environ.get('SSO_API_USERNAME', 'admin')
    password = os.environ.get('SSO_API_PASSWORD', 'admin')

    kc = login(server, user, password)
    realms = kc.admin()

    #  ['keycloak_resource', 'unique identifier']
    resources = [
        ['clients', 'clientId'],
        ['roles', 'name'],
        ['identity-provider', 'alias'],
        ['components', 'name'],
        ['authentication', 'alias'],
        ['groups', 'name'],
        ['client-scopes', 'name'],
    ]

    for realm in realms.all():
        current_realm = realm['realm']

        store = Store(path=output_dir)

        print('publishing: ', realm['id'])

        store.add_child(current_realm)
        store.store_one(realm, 'realm')

        for resource in resources:
            fetch_keycloak_objects = FetchFactory().create(resource, kc, current_realm)
            store.add_child(resource[0])
            fetch_keycloak_objects.fetch(store)
            store.remove_last_child()


def main_cli():
    run()


if __name__ == '__main__':
    run()

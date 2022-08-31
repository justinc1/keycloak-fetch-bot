#!/usr/bin/env python

import os
import sys
from kcapi import OpenID, Token

from kcfetcher.fetch import FetchFactory
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login


def main_token_save_to_file():
    server = os.environ.get('SSO_API_URL', 'https://sso-cvaldezr-stage.apps.sandbox.x8i5.p1.openshiftapps.com/')
    user = os.environ.get('SSO_API_USERNAME', 'admin')
    password = os.environ.get('SSO_API_PASSWORD', 'admin')
    token_filename = os.environ['SSO_TOKEN_FILENAME']
    token = OpenID.createAdminClient(user, password, server).getToken()
    token.save_to_file(open(token_filename, "w"))


def run(output_dir):
    remove_folder(output_dir)
    make_folder(output_dir)

    # Credentials
    server = os.environ.get('SSO_API_URL', 'https://sso-cvaldezr-stage.apps.sandbox.x8i5.p1.openshiftapps.com/')
    token_filename = os.environ.get('SSO_TOKEN_FILENAME')
    if token_filename:
        token = Token(file=open(token_filename, "r"))
        token = token.refresh()
    else:
        user = os.environ.get('SSO_API_USERNAME', 'admin')
        password = os.environ.get('SSO_API_PASSWORD', 'admin')
        token = OpenID.createAdminClient(user, password, server).getToken()

    kc = login(server, token)
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
    output_dir = "output/keycloak"
    run(output_dir)


if __name__ == '__main__':
    sys.stderr.write("Error: invoke dedicated binaries (`kcfetcher` or `kcfetcher_save_token`) instead of this file.\n")
    sys.exit(1)

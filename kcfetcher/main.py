#!/usr/bin/env python

import json
import os
# https://setuptools.pypa.io/en/stable/userguide/datafiles.html#accessing-data-files-at-runtime
# from importlib.resources import files  # py3.10 only
from importlib_resources import files

from kcfetcher.utils import remove_folder, make_folder, remove_ids, normalize, login


class FetchFactory:
    def __init__(self):
        self.strategies = {
            'authentication': CustomAuthenticationFetch,
            'clients': ClientFetch,
        }

    def create(self, resource, kc, realm):
        resource_name = resource[0]
        resource_id = resource[1]

        if resource_name in self.strategies:
            return self.strategies[resource_name](kc, resource_name, resource_id, realm)

        return GenericFetch(kc, resource_name, resource_id, realm)


class GenericFetch:
    def __init__(self, kc, resource_name, resource_id="", realm=""):
        self.kc = kc
        self.resource_name = resource_name
        self.id = resource_id
        self.realm = realm

        blacklist_path = files('kcfetcher.data').joinpath('kcfetcher_blacklist')
        self.black_list = open(blacklist_path).read().split('\n')

    def fetch(self, store_api):
        name = self.resource_name
        identifier = self.id
        realm = self.realm

        print('--> fetching: ', name)

        kc = self.kc.build(name, realm)
        kc_objects = self.all(kc)
        store_api.store(kc_objects, identifier)

    def all(self, kc):
        return filter(lambda fn: not fn[self.id] in self.black_list, kc.all())


class ClientFetch(GenericFetch):
    def fetch(self, store_api):
        name = self.resource_name
        identifier = self.id
        realm = self.realm

        clients_api = self.kc.build(name, realm)

        print('** Client fetching: ', name)
        kc_objects = self.all(clients_api)

        counter = 0
        for kc_object in kc_objects:
            store_api.add_child('client-' + str(counter))  # auth/authentication_name
            store_api.store_one(kc_object, identifier)

            client_roles_query = {'key': 'clientId', 'value': kc_object['clientId']}
            executors = clients_api.roles(client_roles_query).all()
            store_api.add_child('roles')  # auth/authentication_name/executions
            store_api.store_one_with_alias('roles', executors)

            store_api.remove_last_child()  # clients/<clients>/*executions*
            store_api.remove_last_child()  # clients/*clients*
            counter += 1


class CustomAuthenticationFetch(GenericFetch):
    def normalize(self, identifier=""):
        return identifier.lower().replace('//', '_').replace(' ', '_')

    def fetch(self, store_api):
        name = self.resource_name
        identifier = self.id
        realm = self.realm

        authentication_api = self.kc.build(name, realm)

        print('** Authentication fetching: ', name)

        kc_objects = self.all(authentication_api)

        counter = 0
        for kc_object in kc_objects:
            store_api.add_child(self.normalize(kc_object[identifier]))  # auth/authentication_name
            store_api.store_one(kc_object, identifier)

            executors = authentication_api.executions(kc_object).all()
            store_api.add_child('executors')  # auth/authentication_name/executions
            store_api.store_one_with_alias('executors', executors)

            store_api.remove_last_child()  # auth/auth_name/*executions*
            store_api.remove_last_child()  # auth/*authentication_name*
            counter += 1


class Store:
    def __init__(self, path=''):
        self.path = path.split('/')

    def add_child(self, child_name):
        self.path.append(child_name.replace(' ', '_').lower())

    def remove_last_child(self):
        self.path.pop()
        return self

    def __get_relative_path(self):
        return './' + '/'.join(self.path)

    def store_one_with_alias(self, alias, data):
        path = self.__get_relative_path()
        make_folder(path)

        file = open(path + '/' + normalize(alias) + '.json', 'w')
        data = remove_ids(data)
        json.dump(data, file, indent=4, sort_keys=True)
        file.close()

    def store_one(self, data, identifier):
        self.store_one_with_alias(data[identifier], data)

    def store(self, data, identifier):
        for entry in data:
            self.store_one_with_alias(entry[identifier], entry)


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

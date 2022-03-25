import json
import os
from kcapi import Keycloak, OpenID


def login(endpoint, user, password, read_token_from_file=False):
    token = None
    if not read_token_from_file:
        token = OpenID.createAdminClient(user, password).getToken(endpoint)
    else:
        token = open('./token').read()
    return Keycloak(token, endpoint)


def make_folder(name):
    if not os.path.isdir(name):
        os.makedirs(name)


def store_resources(folder_name, resource, identifier):
    make_folder(folder_name)

    file = open(folder_name + '/' + resource[identifier] + '.json', 'w')
    json.dump(resource, file, indent=4, sort_keys=True)
    file.close()


class FetchFactory:
    def __init__(self):
        self.strategies = {
            'authentication': CustomAuthenticationFetch,
            'clients': ClientFetch,
        }

    def create(self, resource, kc):
        if resource[0] in self.strategies:
            return self.strategies[resource[0]](kc)

        return GenericFetch(kc)


class GenericFetch:
    def __init__(self, kc):
        self.kc = kc

    def delegate(self, resource, realm, store_api):
        name = resource[0]
        identifier = resource[1]

        print('--> fetching: ', name)

        kc_objects = self.kc.build(name, realm).all()
        store_api.add_child(name)

        store_api.store(kc_objects, identifier)


class ClientFetch(GenericFetch):
    def delegate(self, resource, realm, store_api):
        name = resource[0]
        identifier = resource[1]

        clients_api = self.kc.build(name, realm)

        print('** Client fetching: ', name)
        kc_objects = clients_api.all()

        store_api.add_child(name)

        for kc_object in kc_objects:
            store_api.add_child(kc_object[identifier])  # auth/authentication_name
            store_api.store_one(kc_object, identifier)

            client_roles_query = {'key': 'clientId', 'value': kc_object['clientId']}
            executors = clients_api.roles(client_roles_query).all()
            store_api.add_child('roles')  # auth/authentication_name/executions
            store_api.store_one_with_alias('roles', executors, 'clientId')

            store_api.remove_last_child()  # auth/auth_name/*executions*
            store_api.remove_last_child()  # auth/*authentication_name*


class CustomAuthenticationFetch(GenericFetch):
    def delegate(self, resource, realm, store_api):
        name = resource[0]
        identifier = resource[1]

        authentication_api = self.kc.build(name, realm)

        print('** Authentication fetching: ', name)
        kc_objects = authentication_api.all()

        store_api.add_child(name)

        for kc_object in kc_objects:
            store_api.add_child(kc_object[identifier])  # auth/authentication_name
            store_api.store_one(kc_object, identifier)

            executors = authentication_api.executions(kc_object).all()
            store_api.add_child('executors')  # auth/authentication_name/executions
            store_api.store_one_with_alias('executors', executors, 'displayName')

            store_api.remove_last_child()  # auth/auth_name/*executions*
            store_api.remove_last_child()  # auth/*authentication_name*


class Store:
    def __init__(self, realm, resource, path=''):
        self.realm = realm
        self.resource = resource
        self.path = path.split('/')

    def add_child(self, child_name):
        self.path.append(child_name.replace(' ', '_').lower())

    def remove_last_child(self):
        self.path.pop()
        return self

    def store_one_with_alias(self, alias, data, identifier):
        path = './' + '/'.join(self.path)
        make_folder(path)

        file = open(path + '/' + alias + '.json', 'w')
        json.dump(data, file, indent=4, sort_keys=True)
        file.close()

    def store_one(self, data, identifier):
        store_resources('./' + '/'.join(self.path), data, identifier)

    def store(self, data, identifier):
        for entry in data:
            store_resources('./' + '/'.join(self.path), entry, identifier)

    def run(self, dfetch):
        dfetch.delegate(self.resource, self.realm, self)


def run():
    make_folder('keycloak')

    # Credentials
    server = 'https://sso1-cvaldezr-stage.apps.sandbox-m2.ll9k.p1.openshiftapps.com/'
    user = 'admin'
    password = 'admin'

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
        realm_folder = 'keycloak/' + realm['realm']
        store_resources(realm_folder, realm, 'realm')
        print('publishing: ', realm['id'])

        for resource in resources:
            fetch_keycloak_objects = FetchFactory().create(resource, kc)
            store = Store(current_realm, resource, path='keycloak/' + realm['realm'])
            store.run(fetch_keycloak_objects)


if __name__ == '__main__':
    run()

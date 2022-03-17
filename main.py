import json
import os
from kcapi import Keycloak, OpenID

token = open('token').read()
server = 'https://sso1-cvaldezr-stage.apps.sandbox-m2.ll9k.p1.openshiftapps.com/'


def get_token(endpoint):
    return OpenID.createAdminClient('admin', 'admin').getToken(endpoint)


def make_folder(name):
    if not os.path.isdir(name):
        os.makedirs(name)


def store_resources(folder_name, resource, identifier):
    make_folder(folder_name)

    file = open(folder_name + '/' + resource[identifier] + '.json', 'w')
    json.dump(resource, file, indent=4, sort_keys=True)
    file.close()


def run():
    make_folder('keycloak')

    _token = get_token(server)
    kc = Keycloak(_token, server)
    realms = kc.admin()

    #            ['keycloak_resource', 'unique identifier']
    resources = [['clients', 'clientId'],
                 ['roles', 'name'],
                 ['identity-provider', 'alias'],
                 ['components', 'name'],
                 ['authentication', 'alias'],
                 ['groups', 'name'],
                 ['client-scopes', 'name']
                ]

    for realm in realms.all():
        current_realm = realm['realm']
        realm_folder = 'keycloak/'+realm['realm']
        store_resources(realm_folder, realm, 'realm')
        print('publishing: ', realm['id'])

        for resource in resources:
            name = resource[0]
            identifier = resource[1]

            print('--> fetching: ', name)
            kc_resources = kc.build(name, current_realm).all()
            for kc_resource in kc_resources:
                store_resources(realm_folder+'/'+name, kc_resource, identifier)


if __name__ == '__main__':
    run()

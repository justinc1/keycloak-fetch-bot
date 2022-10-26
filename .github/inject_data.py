#!/usr/bin/env python
"""
Inject testing data into empty Keycloack instance.
Should just work, if Keycloack instance is empty.
If it is not, remove incomplete objects before running this script.
"""

import logging
import os
from kcapi import OpenID, Keycloak

logging.basicConfig(
    level=logging.DEBUG,
)
logger = logging.getLogger(__name__)


def get_keycloak():
    if os.environ.get("KEYCLOAK_API_CA_BUNDLE") == "":
        # disable annoying warning
        import requests
        requests.packages.urllib3.disable_warnings()

    endpoint = os.environ.get('SSO_API_URL', 'https://localhost:8443/')
    user = os.environ.get('SSO_API_USERNAME', 'admin')
    password = os.environ.get('SSO_API_PASSWORD', 'admin')

    token = OpenID.createAdminClient(user, password, endpoint).getToken()
    return Keycloak(token, endpoint)


def main():
    kc = get_keycloak()
    master_realm = kc.admin()

    # what to add
    realm_name = "ci0-realm"
    role_names_plain = [
        "ci0-role-0",
        "ci0-role-1a",
        "ci0-role-1b",
    ]
    # role_names_composite = {
    #     "ci0-role-1": [  # will contain ci0-role-1a and ci0-role-1b
    #         "ci0-role-1a",
    #         "ci0-role-1b",
    #     ]
    # }
    user_name = "ci0-user"
    group_name = "ci0-group"
    client_scope_name = "ci0-client-scope"

    realm_ids = [realm["id"] for realm in master_realm.all()]
    logger.debug(f"realm_ids={realm_ids}")
    if not realm_name in realm_ids:
        # myrealm = kc.build('realms', realm_name)
        master_realm.create({
            "enabled": "true",
            "id": realm_name,
            "realm": realm_name,
        })

    roles = kc.build('roles', realm_name)
    for role_name in role_names_plain:
        if not roles.findFirst({'key': 'name', 'value': role_name}):
            roles.create({
                "name": role_name,
                "description": role_name + "-desc",
                "attributes": {role_name + "-key0": [role_name + "-value0"]},
            }).isOk()
    # TODO create composite roles
    # for role_name in role_names_composite:
    #     if not roles.findFirst({'key': 'name', 'value': role_name}):
    #         roles.create({
    #             "name": role_name,
    #             "description": role_name + "-desc",
    #             "attributes": {role_name + "-key0": [role_name + "-value0"]},
    #             "composite": True,
    #             "composites": {
    #                 "client": {
    #                     "client-name": []
    #                 },
    #                 "realm": [],
    #                 # role_names_composite[role_name]
    #             }
    #         }).isOk()

    group = kc.build('groups', realm_name)
    # {'key': 'username', 'value': 'batman'}
    # if group_name not in [gg["name"] for gg in group.findAll()]:
    if not group.findFirst({'key': 'name', 'value': group_name}):
        g_creation_state = group.create({
            "name": group_name,
            "attributes": {group_name + "-key0": [group_name + "-value0"]},

        }).isOk()
        # Assign realm role to group
        group_roles_mapping = group.realmRoles({'key': 'name', 'value': group_name})
        group_roles_mapping.add([role_names_plain[0]])

    user = kc.build('users', realm_name)
    if not user.findFirst({'key': 'username', 'value': user_name}):
        u_creation_state = user.create({
            "enabled": "true",
            "username": user_name,
            "firstName": user_name + '-first',
            "lastName": user_name + '-last',
            "attributes": {user_name + "-key0": [user_name + "-value0"]},
            "groups": [group_name],
        }).isOk()
        # TODO assign roles

    client_scopes = kc.build('client-scopes', realm_name)
    if not client_scopes.findFirst({'key': 'name', 'value': client_scope_name}):
        cs_creation_state = client_scopes.create({
            "name": client_scope_name,
            "description": "ci0 client scope",
            "protocol": "openid-connect",
            "attributes": {
                "consent.screen.text": "consent-text-ci0-scope",
                "display.on.consent.screen": "true",
                "include.in.token.scope": "true"
            }
        }).isOk()
        client_scope_id = client_scopes.findFirst({'key': 'name', 'value': client_scope_name})["id"]

        # Assign scope mapping to client scope - set realm role
        role = roles.findFirst({'key': 'name', 'value': "ci0-role-0"})
        client_scope_scope_mappings_realm = kc.build(f"client-scopes/{client_scope_id}/scope-mappings/realm", realm_name)
        client_scope_scope_mappings_realm.create([role])

        # Assign scope mapping to client scope - set client role
        # Just assign some existing client role, view-profile role from client account.
        client_clientId = 'account'
        role_name = "view-profile"
        kc_clients = kc.build(f"clients", realm_name)
        client = kc_clients.findFirst({'key': 'clientId', 'value': client_clientId})
        print(f"client={client}")
        kc_client_roles = kc.build(f"clients/{client['id']}/roles", realm_name)
        role = kc_client_roles.findFirst({'key': 'name', 'value': role_name})
        client_scope_scope_mappings_client = kc.build(f"client-scopes/{client_scope_id}/scope-mappings/clients/{client['id']}", realm_name)
        client_scope_scope_mappings_client.create([role])

        # Assign mapper to client scope
        client_scope_protocol_mapper_many = kc.build(f"client-scopes/{client_scope_id}/protocol-mappers/add-models", realm_name)
        # assign one pre-defined mapper
        client_scope_protocol_mapper_many.create([
            {
                "name": "birthdate",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-attribute-mapper",
                "consentRequired": False,
                "config": {
                    "userinfo.token.claim": "true",
                    "user.attribute": "birthdate",
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                    "claim.name": "birthdate",
                    "jsonType.label": "String",
                }
            }
        ])
        # TODO - create a new mapper
        # client_scope_protocol_mapper_single = kc.build(f"client-scopes/{client_scope_id}/protocol-mappers/models", realm_name)


if __name__ == "__main__":
    main()

#!/usr/bin/env python
"""
Inject testing data into empty Keycloack instance.
Should just work, if Keycloack instance is empty.
If it is not, remove incomplete objects before running this script.
"""

import logging
import os
from copy import copy

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
    client0_client_id = "ci0-client-0"
    client1_client_id = "ci0-client-1"
    # one simple (non-composite) role
    client0_role0_name = "ci0-client0-role0"
    # one composite role, it will contain two other simple roles
    client0_role1_name = "ci0-client0-role1"
    client0_role1a_name = "ci0-client0-role1a"
    client0_role1b_name = "ci0-client0-role1b"
    client0_role_names = [
        client0_role0_name,
        client0_role1_name,
        client0_role1a_name,
        client0_role1b_name,
    ]
    idp_alias = "ci0-idp-saml-0"
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
            "displayName": realm_name + "-display-temp",
            "displayNameHtml": f"<div class=\"kc-logo-text\"><span>{realm_name}</span></div>",
        })
        # How to reproduce https://github.com/justinc1/keycloak-fetch-bot/issues/19
        # Test 1:
        # realm created with:
        #   displayName=ci0-realm-display - code worked
        # realm updated to:
        #   displayName=ci0-realm-displayy - bug exposed
        # realm updated to:
        #   displayName=ci0-realm-display - code again works
        # Looks like on every second update we get bug exposed.
        # So we do an update.
        state = master_realm.update(realm_name, {"displayName": realm_name + "-display"}).isOk()

    auth_flow_api = kc.build('authentication/flows', realm_name)
    auth_flow_browser = auth_flow_api.findFirst({"key": "alias", "value": "browser"})
    client_api = kc.build('clients', realm_name)
    if not client_api.findFirst({'key': 'clientId', 'value': client0_client_id}):
        client_api.create({
            "clientId": client0_client_id,
            "name": client0_client_id + "-name",
            "description": client0_client_id + "-desc",
            "redirectUris": [
                f"https://{client0_client_id}.example.com/redirect-url"
            ],
            # I manually changed a few attributes, and all this was changed in dumped file.
            # Changed attributes:
            #   Backchannel Logout Revoke Offline Sessions
            #   Access Token Signature Algorithm
            #   Exclude Session State From Authentication Response
            #   Access Token Lifespan
            #   Browser Flow
            "attributes": {
                "access.token.lifespan": "600",
                "access.token.signed.response.alg": "ES256",
                "backchannel.logout.revoke.offline.tokens": "false",
                "backchannel.logout.session.required": "false",
                "client_credentials.use_refresh_token": "false",
                "display.on.consent.screen": "false",
                "exclude.session.state.from.auth.response": "true",
                "id.token.as.detached.signature": "false",
                "oauth2.device.authorization.grant.enabled": "false",
                "oidc.ciba.grant.enabled": "false",
                "require.pushed.authorization.requests": "false",
                "saml.artifact.binding": "false",
                "saml.assertion.signature": "false",
                "saml.authnstatement": "false",
                "saml.client.signature": "false",
                "saml.encrypt": "false",
                "saml.force.post.binding": "false",
                "saml.multivalued.roles": "false",
                "saml.onetimeuse.condition": "false",
                "saml.server.signature": "false",
                "saml.server.signature.keyinfo.ext": "false",
                "saml_force_name_id_format": "false",
                "tls.client.certificate.bound.access.tokens": "false",
                "use.refresh.tokens": "true"
            },
            "authenticationFlowBindingOverrides": {
                "browser": auth_flow_browser["id"]
            },
        }).isOk()
    # create also one client with default settings
    if not client_api.findFirst({'key': 'clientId', 'value': client1_client_id}):
        client_api.create({
            "clientId": client1_client_id,
            "name": client1_client_id + "-name",
            "description": client1_client_id + "-desc",
            "redirectUris": [
                f"https://{client1_client_id}.example.com/redirect-url"
            ],

        }).isOk()

    # add SAML identity provider, with 2 mappers
    idp_api = kc.build("identity-provider/instances", realm_name)
    idp_mapper_api = kc.build(f"identity-provider/instances/{idp_alias}/mappers", realm_name)
    if not idp_api.findFirst({'key': 'alias', 'value': idp_alias}):
        idp_api.create({
            "alias": idp_alias,
            "displayName": idp_alias + "-displayName",
            "providerId": "saml",
            "config": {
                "allowCreate": "true",
                "authnContextClassRefs": "[\"aa\",\"bb\"]",
                "authnContextComparisonType": "exact",
                "authnContextDeclRefs": "[\"cc\",\"dd\"]",
                "entityId": "https://172.17.0.2:8443/auth/realms/ci0-realm",
                "nameIDPolicyFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                "principalType": "SUBJECT",
                "signatureAlgorithm": "RSA_SHA256",
                "singleLogoutServiceUrl": "https://172.17.0.6:8443/logout",
                "singleSignOnServiceUrl": "https://172.17.0.6:8443/signon",
                "syncMode": "IMPORT",
                "useJwksUrl": "true",
                "wantAssertionsEncrypted": "true",
                "xmlSigKeyInfoKeyNameTransformer": "KEY_ID"
            },
        }).isOk()
        idp_mapper_api.create({
            "config": {
                "are.attribute.values.regex": "false",
                "attributes": "[{\"key\":\"key0\",\"value\":\"value0\"}]",
                "role": "ci0-role-0",
                "syncMode": "INHERIT"
            },
            "identityProviderAlias": idp_alias,
            "identityProviderMapper": "saml-advanced-role-idp-mapper",
            "name": "idp-mapper-0b"
        })
    # TODO add IdP with providerId=openid, maybe also some pre-defined social one

    # add client roles
    client0 = client_api.findFirst({'key': 'clientId', 'value': client0_client_id})
    client0_roles_api = kc.build(f"clients/{client0['id']}/roles", realm_name)
    for client0_role_name in client0_role_names:
        if not client0_roles_api.findFirst({'key': 'name', 'value': client0_role_name}):
            client0_roles_api.create({
                "name": client0_role_name,
                "description": client0_role_name + "-desc",
                "attributes": {client0_role_name + "-key0": [client0_role_name + "-value0"]},
            }).isOk()

    # TODO add builtin mapper to client
    # TODO add custom mapper to client

    roles_api = kc.build('roles', realm_name)
    for role_name in role_names_plain:
        if not roles_api.findFirst({'key': 'name', 'value': role_name}):
            roles_api.create({
                "name": role_name,
                "description": role_name + "-desc",
                "attributes": {role_name + "-key0": [role_name + "-value0"]},
            }).isOk()
    # TODO create composite roles
    # for role_name in role_names_composite:
    #     if not roles_api.findFirst({'key': 'name', 'value': role_name}):
    #         roles_api.create({
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

    # Make a client role a composite role
    # NOTE - POST /{realm}/clients/{id}/roles/{role-name}/composites requires full RoleRepresentation (per docs).
    # GET /{realm}/clients/{id}/roles returns briefRepresentation, and this seems to work too.
    client0_role1a = client0_roles_api.findFirst({'key': 'name', 'value': client0_role1a_name})
    client0_role1b = client0_roles_api.findFirst({'key': 'name', 'value': client0_role1b_name})
    # Now make client0_role1 a composite
    client0_role1_composite_api = kc.build(f"clients/{client0['id']}/roles/{client0_role1_name}/composites", realm_name)
    client0_role1_composite_api.create([client0_role1a, client0_role1b])


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
        role = roles_api.findFirst({'key': 'name', 'value': "ci0-role-0"})
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

    # TODO add identity-provider
    idp_alias = "ci0-ipd-saml"
    idp_display_name = "CI0 User Fedaration - LDAP"
    # Redirect URI - https://172.17.0.2:8443/auth/realms/ci0-realm/broker/saml/endpoint
    # Service Provider Entity ID - https://172.17.0.2:8443/auth/realms/ci0-realm
    # Single Sign-On Service URL - https://172.17.0.3:443/ - should be some other container

    # TODO add user-federation
    uf0_name = "ci0-uf0-ldap"
    uf1_name = "ci0-uf1-ldap"
    # connection url - ldaps://172.17.0.4:636
    # users dn - ou=users,dc=example,dc=com
    uf0_payload = {
        "config": {
            "allowKerberosAuthentication": [
                "false"
            ],
            "authType": [
                "simple"
            ],
            "batchSizeForSync": [
                "1000"
            ],
            "bindCredential": [
                "ldap-bind-pass"
            ],
            "bindDn": [
                "admin"
            ],
            "cachePolicy": [
                "DEFAULT"
            ],
            "changedSyncPeriod": [
                "-1"
            ],
            "connectionPooling": [
                "true"
            ],
            "connectionUrl": [
                "ldaps://172.17.0.4:636"
            ],
            "debug": [
                "false"
            ],
            "enabled": [
                "true"
            ],
            "fullSyncPeriod": [
                "-1"
            ],
            "importEnabled": [
                "true"
            ],
            "pagination": [
                "true"
            ],
            "priority": [
                "0"
            ],
            "rdnLDAPAttribute": [
                "uid"
            ],
            "searchScope": [
                "1"
            ],
            "syncRegistrations": [
                "false"
            ],
            "trustEmail": [
                "false"
            ],
            "useKerberosForPasswordAuthentication": [
                "false"
            ],
            "useTruststoreSpi": [
                "ldapsOnly"
            ],
            "userObjectClasses": [
                "inetOrgPerson, organizationalPerson"
            ],
            "usernameLDAPAttribute": [
                "uid"
            ],
            "usersDn": [
                "uid"
            ],
            "uuidLDAPAttribute": [
                "nsuniqueid"
            ],
            "validatePasswordPolicy": [
                "false"
            ],
            "vendor": [
                "rhds"
            ]
        },
        "name": uf0_name,
        # "parentId": "deleteme-6",
        "providerId": "ldap",
        "providerType": "org.keycloak.storage.UserStorageProvider"
    }
    uf1_payload = {
        "config": {
            "allowKerberosAuthentication": [
                "false"
            ],
            "authType": [
                "simple"
            ],
            "batchSizeForSync": [
                "1001"
            ],
            "bindCredential": [
                "ldap-bind-pass"
            ],
            "bindDn": [
                "admin1"
            ],
            "cachePolicy": [
                "DEFAULT"
            ],
            "changedSyncPeriod": [
                "-1"
            ],
            "connectionPooling": [
                "true"
            ],
            "connectionUrl": [
                "ldaps://172.17.0.5:636"
            ],
            "debug": [
                "false"
            ],
            "enabled": [
                "true"
            ],
            "fullSyncPeriod": [
                "-1"
            ],
            "importEnabled": [
                "true"
            ],
            "pagination": [
                "true"
            ],
            "priority": [
                "0"
            ],
            "rdnLDAPAttribute": [
                "uid"
            ],
            "searchScope": [
                "1"
            ],
            "syncRegistrations": [
                "false"
            ],
            "trustEmail": [
                "false"
            ],
            "useKerberosForPasswordAuthentication": [
                "false"
            ],
            "useTruststoreSpi": [
                "ldapsOnly"
            ],
            "userObjectClasses": [
                "inetOrgPerson, organizationalPerson"
            ],
            "usernameLDAPAttribute": [
                "uid"
            ],
            "usersDn": [
                "uid"
            ],
            "uuidLDAPAttribute": [
                "nsuniqueid"
            ],
            "validatePasswordPolicy": [
                "false"
            ],
            "vendor": [
                "rhds"
            ]
        },
        "name": uf1_name,
        "providerId": "ldap",
        "providerType": "org.keycloak.storage.UserStorageProvider"
    }
    components_api = kc.build(f"components", realm_name)
    if not components_api.findFirst({'key': 'name', 'value': uf0_name}):
        components_api.create(uf0_payload)
        # TODO add additional mapper to user-federation
    if not components_api.findFirst({'key': 'name', 'value': uf1_name}):
        components_api.create(uf1_payload)


if __name__ == "__main__":
    main()

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
from pytest_unordered import unordered

from kcfetcher.utils import RH_SSO_VERSIONS_7_4, RH_SSO_VERSIONS_7_5

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

"""
TODO keycloak 9.0.3
What needs to be fixed in inject_data.py,
Or is just different.

- client role attributes:
  - are not added to KC
  - if present, they are dumped to disk
- client.json - defaultClientScopes contain also role_list role
- components/rsa-enc-generated.json
  is only in KC 15.0
- components/rsa-generated.json
  in KC 15.0 has also "keyUse": ["sig"] in "config"
- default-roles - are not dumped to disk in KC 9.0, but are in realm.json
- realm.json
    KC 9.0 - in realm.json is "defaultRoles", a simple list of role names
    KC 15.0 - in realm.json in "defaultRole", complex dict, it contains name od default role.
    KC 15 has added ~10 extra values in attributes (cibaAuthRequestedUserHint, oauth2DeviceCodeLifespan, etc)
    KC 15 has added ~10 client related settings (clientOfflineSessionIdleTimeout, clientPolicies, clientProfiles, clientProfiles)

"""

def main():
    kc = get_keycloak()
    master_realm = kc.admin()

    # what to add
    realm_name = "ci0-realm"
    realm_name_old = realm_name + "-OLD"
    client0_client_id = "ci0-client-0"
    client1_client_id = "ci0-client-1"
    # one simple (non-composite) role
    client0_role0_name = "ci0-client0-role0"
    # one composite role, it will contain two other simple client roles
    # and one simple realm role.
    client0_role1_name = "ci0-client0-role1"
    client0_role1a_name = "ci0-client0-role1a"
    client0_role1b_name = "ci0-client0-role1b"
    client0_role_names = [
        client0_role0_name,
        client0_role1_name,
        client0_role1a_name,
        client0_role1b_name,
    ]
    client1_role0_name = "ci0-client1-role0"
    idp_alias = "ci0-idp-saml-0"
    ci0_role0_name = "ci0-role-0"
    ci0_role1_name = "ci0-role-1"
    ci0_role1a_name = "ci0-role-1a"
    ci0_role1b_name = "ci0-role-1b"
    role_names_plain = [
        ci0_role0_name,
        ci0_role1_name,
        ci0_role1a_name,
        ci0_role1b_name,
    ]
    # role_names_composite = {
    #     "ci0-role-1": [  # will contain ci0-role-1a and ci0-role-1b
    #         "ci0-role-1a",
    #         "ci0-role-1b",
    #     ]
    # }
    user_name = "ci0-user"
    group_name = "ci0-group"
    group1a_name = "ci0-group-1a"
    group1b_name = "ci0-group-1b"
    group1c_name = "ci0-group-1c"
    client_scope_name = "ci0-client-scope"

    realm_ids = [realm["id"] for realm in master_realm.all()]
    logger.debug(f"realm_ids={realm_ids}")
    if realm_name_old not in realm_ids:
        # myrealm = kc.build('realms', realm_name)
        master_realm.create({
            "enabled": "true",
            "id": realm_name_old,
            "realm": realm_name_old,
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
        state = master_realm.update(realm_name_old, {
            "realm": realm_name,
            "displayName": realm_name + "-display"
        }).isOk()

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
            "fullScopeAllowed": False,
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
            # Add one builtin and one custom protocol mapper
            # NOTE: this changed also:
            #   ci0-realm/components/allowed_protocol_mapper_types.json
            #     extra values in "allowed-protocol-mapper-types" list
            #     "subType": , from "anonymous" to "authenticated"
            #   ci0-realm/components/creation_date.json - parentId UUID
            #   ci0-realm/components/first_name.json - parentId UUID
            "protocolMappers": [
                {
                    "config": {
                        "access.token.claim": "true",
                        "claim.name": "gender",
                        "id.token.claim": "true",
                        "jsonType.label": "String",
                        "user.attribute": "gender",
                        "userinfo.token.claim": "true"
                    },
                    "consentRequired": False,
                    "name": "gender",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-attribute-mapper"
                },
                {
                    "config": {
                        "access.token.claim": "true",
                        "claim.name": "ci-claim-name",
                        "id.token.claim": "true",
                        "jsonType.label": "String",
                        "user.attribute": "ci-user-property-name",
                        "userinfo.token.claim": "true"
                    },
                    "consentRequired": False,
                    "name": "ci0-client0-mapper-1",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-property-mapper"
                }
            ],
        }).isOk()
    client0 = client_api.findFirst({'key': 'clientId', 'value': client0_client_id})

    # create also one client with default settings
    # Note: name is not mandatory for a client.
    # If not provided, the GET response will not include name attribute!
    if not client_api.findFirst({'key': 'clientId', 'value': client1_client_id}):
        client_api.create({
            "clientId": client1_client_id,
            "description": client1_client_id + "-desc",
            "redirectUris": [
                f"https://{client1_client_id}.example.com/redirect-url"
            ],
        }).isOk()
    client1 = client_api.findFirst({'key': 'clientId', 'value': client1_client_id})

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
    client0_roles_api = kc.build(f"clients/{client0['id']}/roles", realm_name)
    for client0_role_name in client0_role_names:
        if not client0_roles_api.findFirst({'key': 'name', 'value': client0_role_name}):
            role_spec = {
                "name": client0_role_name,
                "description": client0_role_name + "-desc",
                "attributes": {client0_role_name + "-key0": [client0_role_name + "-value0"]},
            }
            client0_roles_api.create(role_spec).isOk()
            if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_4:
                # Add attributes to role also for KC 9.0
                ## role = client0_roles_api.findFirst({'key': 'name', 'value': client0_role_name})
                ## client0_roles_api.update(role["id"], role_spec)  # NO, here we need name.
                client0_roles_api.update(client0_role_name, role_spec)
    client0_role0 = client0_roles_api.findFirst({'key': 'name', 'value': client0_role0_name})
    client0_role1 = client0_roles_api.findFirst({'key': 'name', 'value': client0_role1_name})
    client0_role1a = client0_roles_api.findFirst({'key': 'name', 'value': client0_role1a_name})
    client0_role1b = client0_roles_api.findFirst({'key': 'name', 'value': client0_role1b_name})

    # Add a client role to client1
    client1_roles_api = kc.build(f"clients/{client1['id']}/roles", realm_name)
    if not client1_roles_api.findFirst({'key': 'name', 'value': client1_role0_name}):
        client1_roles_api.create({
            "name": client1_role0_name,
            "description": client1_role0_name + "-desc",
            "attributes": {client1_role0_name + "-key0": [client1_role0_name + "-value0"]},
        }).isOk()
    client1_role0 = client1_roles_api.findFirst({'key': 'name', 'value': client1_role0_name})

    # TODO add builtin mapper to client
    # TODO add custom mapper to client

    roles_api = kc.build('roles', realm_name)
    roles_by_id_api = kc.build("roles-by-id", realm_name)
    for role_name in role_names_plain:
        if not roles_api.findFirst({'key': 'name', 'value': role_name}):
            role_spec = {
                "name": role_name,
                "description": role_name + "-desc",
                # those attributes are silently ignored by KC 9.0
                "attributes": {role_name + "-key0": [role_name + "-value0"]},
            }
            roles_api.create(role_spec).isOk()
            if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_4:
                # Add attributes to role also for KC 9.0
                role = roles_api.findFirst({'key': 'name', 'value': role_name})
                roles_api.update(role["id"], role_spec)

    ci0_role0 = roles_api.findFirst({'key': 'name', 'value': ci0_role0_name})
    ci0_role1 = roles_api.findFirst({'key': 'name', 'value': ci0_role1_name})
    ci0_role1a = roles_api.findFirst({'key': 'name', 'value': ci0_role1a_name})
    ci0_role1b = roles_api.findFirst({'key': 'name', 'value': ci0_role1b_name})

    # Make ci0_role0_name realm role a default realm role
    logger.debug('-'*80)
    realm = master_realm.get(realm_name).verify().resp().json()
    if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_4:
        # RH SSO 7.4 - PUT https://172.17.0.2:8443/auth/admin/realms/ci0-realm
        realm_default_roles = realm["defaultRoles"]
        if ci0_role0_name not in realm_default_roles:
            realm_default_roles.append(ci0_role0_name)
            state = master_realm.update(realm_name, {"defaultRoles": realm_default_roles}).isOk()
        assert ci0_role0_name in master_realm.get(realm_name).verify().resp().json()["defaultRoles"]
    else:
        assert kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_5
        # RH SSO 7.5 - POST https://172.17.0.2:8443/auth/admin/realms/ci0-realm/roles-by-id/f64c449c-f8f0-4435-84ae-e459e20e6e28/composites
        # https://172.17.0.2:8443/auth/admin/realms/ci0-realm/roles-by-id/f64c449c-f8f0-4435-84ae-e459e20e6e28/composites
        # Interesting, renaming realm does not rename corresponding "default-roles-..." role.
        ci0_default_roles = roles_api.findFirst({'key': 'name', 'value': "default-roles-" + realm["id"]})

        # both work
        # ci0_default_roles_composites_api = kc.build(f"roles-by-id/{ci0_default_roles['id']}/composites", realm_name)
        ci0_default_roles_composites_api = roles_by_id_api.get_child(roles_by_id_api, ci0_default_roles['id'], "composites")

        # logger.debug(f"ci0_role0={ci0_role0}")
        ci0_default_roles_composites_api.create([ci0_role0])
        composites = roles_by_id_api.get(f"{ci0_default_roles['id']}/composites").verify().resp().json()
        composites_names = [cc["name"] for cc in composites]
        logger.debug(f"composites_names={composites_names}")
        assert composites_names == unordered([
            ci0_role0_name,
            "offline_access", "uma_authorization",  # default realm roles
            "manage-account", "view-profile",  # default client roles, from account client
        ])


    # Make ci0_client0_role0_name client role a default realm role
    client0 = client_api.findFirst({'key': 'clientId', 'value': client0_client_id})
    if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_4:
        # RH SSO 7.4 - PUT https://172.17.0.2:8443/auth/admin/realms/ci0-realm/clients/864618ea-f1fe-484e-bd73-0517c96668ff
        # findFirst() - uses different endpoint, might return a bit different result (like /roles and briefRepresentation).
        # client0 = client_api.get(client0["id"]).verify().resp().json()
        # empty defaultRoles - whole attribute is missing.
        client0_default_roles = client0.get("defaultRoles", [])
        if client0_role0_name not in client0_default_roles:
            client0_default_roles.append(client0_role0_name)
            # we can update only whole top-level attributes. update() uses a very simple dict-merge.
            state = client_api.update(client0["id"], {"defaultRoles": client0_default_roles}).isOk()
        assert client0_role0_name in client_api.get(client0["id"]).verify().resp().json()["defaultRoles"]
    else:
        assert kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_5
        # RH SSO 7.5 - POST https://172.17.0.2:8443/auth/admin/realms/ci0-realm/roles-by-id/f64c449c-f8f0-4435-84ae-e459e20e6e28/composites
        ci0_default_roles = roles_api.findFirst({'key': 'name', 'value': "default-roles-" + realm["id"]})
        ci0_default_roles_composites_api = roles_by_id_api.get_child(roles_by_id_api, ci0_default_roles['id'], "composites")
        ci0_default_roles_composites_api.create([client0_role0])
        composites = roles_by_id_api.get(f"{ci0_default_roles['id']}/composites").verify().resp().json()
        composites_names = [cc["name"] for cc in composites]
        logger.debug(f"composites_names={composites_names}")
        assert composites_names == unordered([
            ci0_role0_name,
            client0_role0_name,
            "offline_access", "uma_authorization",  # default realm roles
            "manage-account", "view-profile",  # default client roles, from account client
        ])

    # Create composite realm role
    role_composite_api = kc.build(f"/roles/{ci0_role1_name}/composites", realm_name)
    role_composite_api.create([ci0_role1a, ci0_role1b, client0_role1a])
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
    # Now make client0_role1 a composite
    client0_role1_composite_api = kc.build(f"clients/{client0['id']}/roles/{client0_role1_name}/composites", realm_name)
    client0_role1_composite_api.create([ci0_role1a, client0_role1a, client0_role1b])

    # ci0-client-0 has fullScopeAllowed=False, set additional realm and client roles under Scope Mappings.
    # https://172.17.0.2:8443/auth/admin/realms/ci0-realm/clients/95f35572-457c-4358-8a87-4157cb471840/scope-mappings/realm
    client0_scope_mappings_realm_api = kc.build(f"clients/{client0['id']}/scope-mappings/realm", realm_name)
    client0_scope_mappings_realm_api.create([ci0_role0, ci0_role1b])

    # Also assign some client roles to client Scope Mappings.
    # The client roles must be from a different client.
    client0_scope_mappings_client_api = kc.build(f"clients/{client0['id']}/scope-mappings/clients/{client1['id']}", realm_name)
    client0_scope_mappings_client_api.create([client1_role0])

    groups_api = kc.build('groups', realm_name)
    # {'key': 'username', 'value': 'batman'}
    # if group_name not in [gg["name"] for gg in group.findAll()]:
    if not groups_api.findFirst({'key': 'name', 'value': group_name}):
        g_creation_state = groups_api.create({
            "name": group_name,
            "attributes": {group_name + "-key0": [group_name + "-value0"]},
        }).isOk()
        # Assign realm role to group
        group_roles_mapping = groups_api.realmRoles({'key': 'name', 'value': group_name})
        group_roles_mapping.add([role_names_plain[0]])

    # group with subgroup
    # hierarchy is group1a -> group1b -> group1c
    # POST https://172.17.0.2:8443/auth/admin/realms/ci0-realm/groups/92a517f4-4134-4bb0-9cab-5fd0107d9ff1/children
    if not groups_api.findFirst({'key': 'name', 'value': group1a_name}):
        groups_api.create({
            "name": group1a_name,
            "attributes": {group1a_name + "-key0": [group1a_name + "-value0"]},
        }).isOk()
    group1a = groups_api.findFirst({'key': 'name', 'value': group1a_name})
    group1a_id = group1a["id"]
    group1a_children_api = groups_api.get_child(groups_api, group1a_id, "children")
    group1a_children_api.create({"name": group1b_name})
    # refresh group1a to get group1b id
    group1a = groups_api.findFirst({'key': 'name', 'value': group1a_name})
    assert group1b_name == group1a["subGroups"][0]["name"]
    group1b_id = group1a["subGroups"][0]["id"]
    group1b_children_api = groups_api.get_child(groups_api, group1b_id, "children")
    group1b_children_api.create({"name": group1c_name})

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
        client_scope_scope_mappings_realm = kc.build(f"client-scopes/{client_scope_id}/scope-mappings/realm", realm_name)
        client_scope_scope_mappings_realm.create([ci0_role0])

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

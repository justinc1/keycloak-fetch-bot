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
    master_realm_api = kc.admin()

    # what to add
    realm_name = "ci0-realm"
    realm_name_old = realm_name + "-OLD"
    client0_client_id = "ci0-client-0"
    client1_client_id = "ci0-client-1"
    client2_client_id = "ci0-client-2-saml"
    client3_client_id = "ci0-client-3-saml"
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
    client2_role0_name = "ci0-client2-role0"
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
    client_scope_0_name = "ci0-client-scope"
    client_scope_1_name = "ci0-client-scope-1-saml"
    client_scope_2_name = "ci0-client-scope-2-saml"

    realm_ids = [realm["id"] for realm in master_realm_api.all()]
    logger.debug(f"realm_ids={realm_ids}")
    if realm_name_old not in realm_ids:
        # myrealm = kc.build('realms', realm_name)
        master_realm_api.create({
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
        state = master_realm_api.update(realm_name_old, {
            "realm": realm_name,
            "displayName": realm_name + "-display"
        }).isOk()
    ci0_realm = master_realm_api.findFirstByKV("realm", realm_name)

    ## NO: auth_api = kc.build('authentication', realm_name)
    auth_api = master_realm_api.get_child(master_realm_api, realm_name, "authentication")
    auth_flow_api = kc.build('authentication/flows', realm_name)
    auth_required_actions_api = kc.build('authentication/required-actions', realm_name)
    auth_executions_api = kc.build('authentication/executions', realm_name)
    auth_flow_browser = auth_flow_api.findFirst({"key": "alias", "value": "browser"})

    auth_flow_generic_alias = "ci0-auth-flow-generic"
    if not auth_flow_api.findFirstByKV("alias", auth_flow_generic_alias):
        auth_flow_api.create({
            "alias": auth_flow_generic_alias,
            "providerId": "basic-flow",
            "description": "ci0-auth-flow-generic-desc",
            "topLevel": True,
            "builtIn": False,
        })
        if 0:
            # Looks like PUT /{realm}/authentication/flows/{id} exists, but is not usable.
            # In UI edit is not possible, and API returns 409/500 error.
            auth_flow_generic = auth_flow_api.findFirstByKV("alias", auth_flow_generic_alias)
            data_change = {
                "description": "ci0-auth-flow-generic-desc---NEW",
            }
            # auth_flow_api.update(auth_flow_generic["id"], data_change)  # 409 error
            data_new = copy(auth_flow_generic)
            data_new.update(data_change)
            auth_flow_api.update(auth_flow_generic["id"], data_new)  # 500 error

        # auth_flow_generic = auth_flow_api.findFirstByKV("alias", auth_flow_generic_alias)
        this_flow_executions_api = auth_flow_api.get_child(auth_flow_api, auth_flow_generic_alias, "executions")
        this_flow_executions_execution_api = this_flow_executions_api.get_child(this_flow_executions_api, "", "execution")
        this_flow_executions_flow_api = this_flow_executions_api.get_child(this_flow_executions_api, "", "flow")
        # create two executions
        this_flow_executions_execution_api.create({"provider": "direct-grant-validate-username"})
        this_flow_executions_execution_api.create({"provider": "auth-conditional-otp-form"})

        # make the second execution "alternative"
        executions = this_flow_executions_api.all()
        assert 2 == len(executions)
        assert "auth-conditional-otp-form" == executions[1]["providerId"]
        assert "Conditional OTP Form" == executions[1]["displayName"]
        assert "DISABLED" == executions[1]["requirement"]
        assert "ALTERNATIVE" in executions[1]["requirementChoices"]
        execution1_temp = copy(executions[1])
        execution1_temp.update(dict(requirement="ALTERNATIVE"))
        # PUT https://172.17.0.2:8443/auth/admin/realms/ci0-realm/authentication/flows/ci0-auth-flow-generic/executions
        this_flow_executions_api.update("", execution1_temp)

        # configure the second execution
        # GET https://172.17.0.2:8443/auth/admin/realms/ci0-realm/authentication/flows/ci0-auth-flow-generic/executions
        # POST https://172.17.0.2:8443/auth/admin/realms/ci0-realm/authentication/executions/a418c71e-f2f3-4d17-883b-9d17ccecda29/config
        assert "authenticationConfig" not in executions[1]  # since authenticationConfig was not yet created
        execution1_id = executions[1]["id"]
        execution1_config_api = auth_executions_api.get_child(auth_executions_api, execution1_id, "config")
        execution1_config_api.create({
            "config": {
                "otpControlAttribute": "user-attr",
                "skipOtpRole": "ci0-role-1",
                "forceOtpRole": "ci0-client-0.ci0-client0-role0",
                "noOtpRequiredForHeaderPattern": "ci0-skip-header",
                "forceOtpForHeaderPattern": "ci0-force-header",
                "defaultOtpOutcome": "skip"
            },
            "alias": "ci0-auth-flow-generic-exec-20-alias"
        })

        # To get a second level, we add a 3rd execution, with provider of type flow
        # That execution can have its own "childs" - a second level.
        # POST https://172.17.0.2:8443/auth/admin/realms/ci0-realm/authentication/flows/ci0-auth-flow-generic/executions/flow
        # Flow type: generic
        this_flow_executions_flow_api.create({
            "alias": "ci0-auth-flow-generic-exec-3-generic-alias",
            "type": "basic-flow",
            "description": "ci0-auth-flow-generic-exec-3-generic-alias-desc",
            "provider": "registration-page-form",
        })
        # Flow type: flow
        this_flow_executions_flow_api.create({
            "alias": "ci0-auth-flow-generic-exec-4-flow-alias",
            "type": "form-flow",
            "description": "ci0-auth-flow-generic-exec-4-flow-alias-desc",
            "provider": "registration-page-form",
        })

        executions = this_flow_executions_api.all()
        # Make 3rd execution CONDITIONAL
        assert "ci0-auth-flow-generic-exec-3-generic-alias" == executions[2]["displayName"]
        execution2_temp = copy(executions[2])
        execution2_temp.update(dict(requirement="CONDITIONAL"))
        this_flow_executions_api.update("", execution2_temp)
        # Make 4th execution REQUIRED
        assert "ci0-auth-flow-generic-exec-4-flow-alias" == executions[3]["displayName"]
        execution3_temp = copy(executions[3])
        execution3_temp.update(dict(requirement="REQUIRED"))
        this_flow_executions_api.update("", execution3_temp)

        # Add child flow to 3rd execution, type generic
        # NOTE: this will change order in executions - this_flow_executions_api.all() returns ordered list
        # POST https://172.17.0.2:8443/auth/admin/realms/ci0-realm/authentication/flows/ci0-auth-flow-generic-exec-3-generic-alias/executions/flow
        the_3rd_flow_alias = "ci0-auth-flow-generic-exec-3-generic-alias"
        the_3rd_flow_executions_flow_api = auth_flow_api.get_child(auth_flow_api, the_3rd_flow_alias, "executions/flow")
        the_3rd_flow_executions_flow_api.create({
            "alias": "ci0-auth-flow-generic-exec-3-1-flow-alias",
            "type": "basic-flow",
            "description": "ci0-auth-flow-generic-exec-3-1-flow-alias-desc",
            "provider": "registration-page-form"
        })
        # make it ALTERNATIVE
        executions = this_flow_executions_api.all()
        assert "ci0-auth-flow-generic-exec-3-1-flow-alias" == executions[3]["displayName"]
        execution_temp = copy(executions[3])
        execution_temp.update(dict(requirement="ALTERNATIVE"))
        this_flow_executions_api.update("", execution_temp)

        # Add child execution to 4th execution, select recaptcha
        the_4th_flow_alias = "ci0-auth-flow-generic-exec-4-flow-alias"
        the_4th_flow_executions_execution_api = auth_flow_api.get_child(auth_flow_api, the_4th_flow_alias, "executions/execution")
        the_4th_flow_executions_execution_api.create({"provider": "registration-recaptcha-action"})
        # leave it disabled
        executions = this_flow_executions_api.all()
        assert "registration-recaptcha-action" == executions[5]["providerId"]
        assert "DISABLED" == executions[5]["requirement"]
        # configure it 754
        execution5_id = executions[5]["id"]
        execution5_config_api = auth_executions_api.get_child(auth_executions_api, execution5_id, "config")
        execution5_config_api.create({
            "config": {
                "site.key": "ci0-recaptcha-site-key",
                "secret": "ci0-recaptcha-secret",
                "useRecaptchaNet": "true"
            },
            "alias": "ci0-auth-flow-generic-exec-6-alias"
        })

    # reconfigure Authentication - xyz
    realm_data_old = master_realm_api.get(realm_name).verify().resp().json()
    realm_data_new = copy(realm_data_old)
    realm_data_update_1 = {
        # ------------------------------------------------------------------
        # Authentication - bindings
        "resetCredentialsFlow": "ci0-auth-flow-generic",
        # ------------------------------------------------------------------
        # Authentication - password policy
        "passwordPolicy": "forceExpiredPasswordChange(365) and upperCase(2)",
        # ------------------------------------------------------------------
        # Authentication - OTP policy
        # Default values:
        #     "otpPolicyType": "totp",
        #     "otpPolicyAlgorithm": "HmacSHA1",
        #     "otpPolicyDigits": 6,
        #     "otpPolicyInitialCounter": 0,
        #     "otpPolicyLookAheadWindow": 1,
        #     "otpPolicyPeriod": 30,
        #     "otpSupportedApplications": [
        #             "FreeOTP",
        #             "Google Authenticator"
        #     ]
        "otpPolicyType": "hotp",
        "otpPolicyAlgorithm": "HmacSHA256",
        "otpPolicyDigits": 8,
        "otpPolicyInitialCounter": 3,
        "otpPolicyLookAheadWindow": 2,
        "otpPolicyPeriod": 30,
        "otpSupportedApplications": [
            "FreeOTP"
        ],
    }
    realm_data_update_2 = {
        # ------------------------------------------------------------------
        # Authentication - WebAuthn Policy
        # Default values
        #     "webAuthnPolicyAttestationConveyancePreference": "not specified",
        #     "webAuthnPolicyAuthenticatorAttachment": "not specified",
        #     "webAuthnPolicyAvoidSameAuthenticatorRegister": false,
        #     "webAuthnPolicyCreateTimeout": 0,
        #     "webAuthnPolicyRequireResidentKey": "not specified",
        #     "webAuthnPolicyRpId": "",
        #     "webAuthnPolicySignatureAlgorithms": [
        #         "ES256"
        #     ],
        #     "webAuthnPolicyUserVerificationRequirement": "not specified",
        #     "webAuthnPolicyAcceptableAaguids": [],
        "webAuthnPolicyAttestationConveyancePreference": "indirect",
        "webAuthnPolicyAuthenticatorAttachment": "platform",
        "webAuthnPolicyAvoidSameAuthenticatorRegister": True,
        "webAuthnPolicyCreateTimeout": 2,
        "webAuthnPolicyRequireResidentKey": "Yes",
        "webAuthnPolicyRpEntityName": "keycloak",
        "webAuthnPolicyRpId": "ci0.example.com",
        "webAuthnPolicySignatureAlgorithms": [
            "ES384",
            "ES512"
        ],
        "webAuthnPolicyUserVerificationRequirement": "required",
        "webAuthnPolicyAcceptableAaguids": [
            "ci0-aaguid-0"
        ],
        # ------------------------------------------------------------------
        # Authentication - webAuthnPolicyPasswordless
        "webAuthnPolicyPasswordlessAcceptableAaguids": [
            "cio-aaguid-1"
        ],
        "webAuthnPolicyPasswordlessAttestationConveyancePreference": "none",
        "webAuthnPolicyPasswordlessAuthenticatorAttachment": "platform",
        "webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister": True,
        "webAuthnPolicyPasswordlessCreateTimeout": 4,
        "webAuthnPolicyPasswordlessRequireResidentKey": "No",
        "webAuthnPolicyPasswordlessRpId": "ci0-RpId",
        "webAuthnPolicyPasswordlessSignatureAlgorithms": [
            "ES512",
            "RS256"
        ],
        "webAuthnPolicyPasswordlessUserVerificationRequirement": "preferred",
    }
    # reconfigure realm security-defenses
    realm_data_update_3 = {
        "browserSecurityHeaders": {
            "contentSecurityPolicy": "frame-src 'self'; frame-ancestors 'self'; object-src 'none-b';",
            "contentSecurityPolicyReportOnly": "c",
            "strictTransportSecurity": "max-age=31536000; includeSubDomains-g",
            "xContentTypeOptions": "nosniff-d",
            "xFrameOptions": "SAMEORIGIN-a",
            "xRobotsTag": "none-e",
            "xXSSProtection": "1; mode=block-f"
        },
        "bruteForceProtected": True,
        "failureFactor": 31,
        "maxDeltaTimeSeconds": 61200,
        "maxFailureWaitSeconds": 960,
        "minimumQuickLoginWaitSeconds": 240,
        "quickLoginCheckMilliSeconds": 1003,
        "waitIncrementSeconds": 120,
    }
    # Surprise. KC 9.02 - on first update, "WebAuthn Policy" changes were not applied.
    # Do it a second time, or split update into two parts.
    # Update: the real problem was a partial update - see commit 2bdd5b5851e96548042ffceb786ea51f0b2fe78d.
    realm_data_new.update(realm_data_update_1)
    state = master_realm_api.update(realm_name, realm_data_new).isOk()
    realm_data_new.update(realm_data_update_2)
    realm_data_new.update(realm_data_update_3)
    #
    state = master_realm_api.update(realm_name, realm_data_new).isOk()
    # check what is in server
    assert_realm_authentication(master_realm_api, realm_name)

    # Authentication - required actions
    # GET https://172.17.0.2:8443/auth/admin/realms/ci0-realm/authentication/required-actions
    # Reconfigure two existing required actions
    # PUT https://172.17.0.2:8443/auth/admin/realms/ci0-realm/authentication/required-actions/CONFIGURE_TOTP
    # {"alias":"CONFIGURE_TOTP","name":"Configure OTP","providerId":"CONFIGURE_TOTP","enabled":true,"defaultAction":false,"priority":10,"config":{}}
    required_actions = auth_required_actions_api.get(None).verify().resp().json()
    required_actions_aliases = [obj['alias'] for obj in required_actions]
    assert "CONFIGURE_TOTP" in required_actions[0]["alias"]
    if required_actions[0]["defaultAction"] is not True:
        req_action_new = copy(required_actions[0])
        assert req_action_new["enabled"] is True
        req_action_new["defaultAction"] = True
        state = auth_required_actions_api.update(req_action_new["alias"], req_action_new)
        del req_action_new
    assert "terms_and_conditions" in required_actions[1]["alias"]
    if required_actions[1]["enabled"] is not True:
        req_action_new = copy(required_actions[1])
        req_action_new["enabled"] = True
        state = auth_required_actions_api.update(req_action_new["alias"], req_action_new)
        del req_action_new
    # Create/register a new required-action
    # To figure out, what can be registered:
    # GET https://172.17.0.2:8443/auth/admin/realms/ci0-realm/authentication/unregistered-required-actions
    # [{"providerId":"webauthn-register-passwordless","name":"Webauthn Register Passwordless"},{"providerId":"webauthn-register","name":"Webauthn Register"}]
    # POST https://172.17.0.2:8443/auth/admin/realms/ci0-realm/authentication/register-required-action
    # {"providerId":"webauthn-register","name":"Webauthn Register"}
    if "webauthn-register" not in required_actions_aliases:
        unregistered_required_actions = auth_api.get("unregistered-required-actions").verify().resp().json()
        for req_action_new in unregistered_required_actions:
            if "webauthn-register" == req_action_new["providerId"]:
                break
        assert "webauthn-register" == req_action_new["providerId"]
        auth_register_required_action_api = auth_api.get_child(auth_api, "register-required-action", None)
        auth_register_required_action_api.create(req_action_new).isOk()
        # BUG - call .create() again, and we have two copies
        # auth_register_required_action_api.create(req_action_new).isOk()
        # req_action_new is last in list. Move it higher
        # POST https://172.17.0.2:8443/auth/admin/realms/ci0-realm/authentication/required-actions/webauthn-register/raise-priority
        # {"realm":"ci0-realm","alias":"webauthn-register"}
        auth_required_actions_webauthn_register_raise_priority_api = auth_required_actions_api.get_child(auth_required_actions_api, "webauthn-register", "raise-priority")
        auth_required_actions_webauthn_register_raise_priority_api.create({
            "realm": realm_name,
            "alias": "webauthn-register",
        })

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
    assert_realm_authentication(master_realm_api, realm_name)

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
    assert_realm_authentication(master_realm_api, realm_name)

    # create a SAML client, with roles etc.
    if not client_api.findFirst({'key': 'clientId', 'value': client2_client_id}):
        # POST https://172.17.0.2:8443/auth/admin/realms/ci0-realm/clients
        # {"enabled":true,"attributes":{},"redirectUris":[],"protocol":"saml","clientId":"ci0-client-2-saml","adminUrl":"http://the-saml.com"}
        client_api.create({
            "enabled": True,
            "attributes": {},
            "redirectUris": [
                f"https://{client2_client_id}.example.com/redirect-url",
            ],
            "protocol": "saml",
            "clientId": client2_client_id,
            "adminUrl": f"http://{client2_client_id}-admin-url.example.com"
        }).isOk()
        client2 = client_api.findFirst({'key': 'clientId', 'value': client2_client_id})
        client2_id = client2["id"]
        client2_new = copy(client2)
        client2_new.update({
            "name": client2_client_id + "-name",
            "description": client2_client_id + "-desc",
        })
        client2_new["attributes"].update({
            "saml_assertion_consumer_url_post": "http://saml-admin-url-post.example.com",
            "saml.assertion.lifespan": 120,
        })
        client2_new["authenticationFlowBindingOverrides"].update({
            "browser": auth_flow_browser["id"],
        })
        client_api.update(client2_id, client2_new)

        # add builtin protocol mapper
        # POST https://172.17.0.2:8443/auth/admin/realms/ci0-realm/clients/2eb30cd6-628d-47cd-9943-373d73f81785/protocol-mappers/add-models
        # [{"name":"X500 email","protocol":"saml","protocolMapper":"saml-user-property-mapper","consentRequired":false,"config":{"attribute.nameformat":"urn:oasis:names:tc:SAML:2.0:attrname-format:uri","user.attribute":"email","friendly.name":"email","attribute.name":"urn:oid:1.2.840.113549.1.9.1"}}]
        client2_protocol_mappers_add_models_api = client_api.get_child(client_api, client2_id, "protocol-mappers/add-models")
        client2_protocol_mappers_add_models_api.create([{
            "name": "X500 email",
            "protocol": "saml",
            "protocolMapper": "saml-user-property-mapper",
            "consentRequired": False,
            "config": {
                "attribute.nameformat": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                "user.attribute": "email",
                "friendly.name": "email",
                "attribute.name": "urn:oid:1.2.840.113549.1.9.1",
            },
        }]).isOk()

        # add custom protocol mapper
        # POST https://172.17.0.2:8443/auth/admin/realms/ci0-realm/clients/2eb30cd6-628d-47cd-9943-373d73f81785/protocol-mappers/models
        # {"protocol":"saml","config":{"Script":"/**/\n//insert your code here...","single":"true","friendly.name":"ci0-client-2-saml-mapper-js-friedly","attribute.name":"ci0-client-2-saml-mapper-attr-name","attribute.nameformat":"Basic"},"name":"ci0-client-2-saml-mapper-js","protocolMapper":"saml-javascript-mapper"}
        client2_protocol_mappers_models_api = client_api.get_child(client_api, client2_id, "protocol-mappers/models")
        client2_protocol_mappers_models_api.create({
            "protocol": "saml",
            "config": {
                "Script": "/**/\n//insert your code here...",
                "single": "true",
                "friendly.name": "ci0-client-2-saml-mapper-js-friedly",
                "attribute.name": "ci0-client-2-saml-mapper-attr-name",
                "attribute.nameformat": "Basic",
            },
            "name": "ci0-client-2-saml-mapper-js",
            "protocolMapper": "saml-javascript-mapper",
        }).isOk()
    client2 = client_api.findFirst({'key': 'clientId', 'value': client2_client_id})

    # create default SAML client - no roles etc
    if not client_api.findFirst({'key': 'clientId', 'value': client3_client_id}):
        # POST https://172.17.0.2:8443/auth/admin/realms/ci0-realm/clients
        # {"enabled":true,"attributes":{},"redirectUris":[],"protocol":"saml","clientId":"ci0-client-2-saml","adminUrl":"http://the-saml.com"}
        client_api.create({
            "enabled": True,
            "attributes": {},
            "redirectUris": [],
            "protocol": "saml",
            "clientId": client3_client_id,
            "adminUrl": f"http://{client3_client_id}-admin-url.example.com"
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
        # This IdP mapper is suitable for RH SSO 7.5.
        # 7.4 does load it, but type "saml-advanced-role-idp-mapper" is not recognized.
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
        # This IdP mapper is suitable for RH SSO 7.4
        idp_mapper_api.create({
            "identityProviderAlias": idp_alias,
            "config": {
                "attribute.name": "attr-name",
                "attribute.friendly.name": "attr-friendly-name",
                "attribute.value": "attr-value",
                "role": "ci0-client-0.ci0-client0-role0"
            },
            "name": "idp-mapper-1",
            "identityProviderMapper": "saml-role-idp-mapper",
        })
    assert_realm_authentication(master_realm_api, realm_name)

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
    assert_realm_authentication(master_realm_api, realm_name)

    # Add a client role to client1
    client1_roles_api = kc.build(f"clients/{client1['id']}/roles", realm_name)
    if not client1_roles_api.findFirst({'key': 'name', 'value': client1_role0_name}):
        role_spec = {
            "name": client1_role0_name,
            "description": client1_role0_name + "-desc",
            "attributes": {client1_role0_name + "-key0": [client1_role0_name + "-value0"]},
        }
        client1_roles_api.create(role_spec).isOk()
        if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_4:
            # Add attributes to role also for KC 9.0
            client1_roles_api.update(client1_role0_name, role_spec).isOk()
    client1_role0 = client1_roles_api.findFirst({'key': 'name', 'value': client1_role0_name})
    assert_realm_authentication(master_realm_api, realm_name)

    client2_roles_api = kc.build(f"clients/{client2['id']}/roles", realm_name)
    if not client2_roles_api.findFirst({'key': 'name', 'value': client2_role0_name}):
        role_spec = {
            "name": client2_role0_name,
            "description": client2_role0_name + "-desc",
            "attributes": {client2_role0_name + "-key0": [client2_role0_name + "-value0"]},
        }
        client2_roles_api.create(role_spec).isOk()
        if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_4:
            # Add attributes to role also for KC 9.0
            client2_roles_api.update(client2_role0_name, role_spec).isOk()
    client2_role0 = client2_roles_api.findFirst({'key': 'name', 'value': client2_role0_name})

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
    assert_realm_authentication(master_realm_api, realm_name)

    # Make ci0_role0_name realm role a default realm role
    logger.debug('-'*80)
    realm_data_old = master_realm_api.get(realm_name).verify().resp().json()
    realm_data_new = copy(realm_data_old)
    if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_4:
        # RH SSO 7.4 - PUT https://172.17.0.2:8443/auth/admin/realms/ci0-realm
        if ci0_role0_name not in realm_data_new["defaultRoles"]:
            realm_data_new["defaultRoles"].append(ci0_role0_name)
            state = master_realm_api.update(realm_name, realm_data_new).isOk()
        assert ci0_role0_name in master_realm_api.get(realm_name).verify().resp().json()["defaultRoles"]
    else:
        assert kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_5
        # RH SSO 7.5 - POST https://172.17.0.2:8443/auth/admin/realms/ci0-realm/roles-by-id/f64c449c-f8f0-4435-84ae-e459e20e6e28/composites
        # https://172.17.0.2:8443/auth/admin/realms/ci0-realm/roles-by-id/f64c449c-f8f0-4435-84ae-e459e20e6e28/composites
        # Interesting, renaming realm does not rename corresponding "default-roles-..." role.
        ci0_default_roles = roles_api.findFirst({'key': 'name', 'value': "default-roles-" + realm_data_old["id"]})

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

    # This one was failing.
    # Call to "master_realm_api.update(realm_name, {"defaultRoles": realm_default_roles}).isOk()" destroyed
    # webAuthnPolicy and webAuthnPolicyPasswordless configuration.
    # We MUST use READ-MODIFY-WRITE to send full realm data to each .update() call.
    assert_realm_authentication(master_realm_api, realm_name)


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
        ci0_default_roles = roles_api.findFirst({'key': 'name', 'value': "default-roles-" + realm_data_old["id"]})
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
    assert_realm_authentication(master_realm_api, realm_name)

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
    assert_realm_authentication(master_realm_api, realm_name)

    # scope mappings for client ci0-client-2-saml
    # GUI: "full scope allowed" to off
    # PUT https://172.17.0.2:8443/auth/admin/realms/ci0-realm/clients/17033bb3-0430-46d9-8053-88e56ea62d1d
    # full payload, with 'fullScopeAllowed: False'
    # {"id":"17033bb3-0430-46d9-8053-88e56ea62d1d","clientId":"ci0-client-2-saml","name":"ci0-client-2-saml-name","description":"ci0-client-2-saml-desc","adminUrl":"http://ci0-client-2-saml-admin-url.example.com","surrogateAuthRequired":false,"enabled":true,"alwaysDisplayInConsole":false,"clientAuthenticatorType":"client-secret","redirectUris":["https://ci0-client-2-saml.example.com/redirect-url"],"webOrigins":["https://ci0-client-2-saml.example.com"],"notBefore":0,"bearerOnly":false,"consentRequired":false,"standardFlowEnabled":true,"implicitFlowEnabled":false,"directAccessGrantsEnabled":false,"serviceAccountsEnabled":false,"publicClient":false,"frontchannelLogout":true,"protocol":"saml","attributes":{"saml.force.post.binding":"true","saml_assertion_consumer_url_post":"http://saml-admin-url-post.example.com","saml.server.signature":"true","saml.signing.certificate":"MIICsTCCAZkCBgGFLnwu5TANBgkqhkiG9w0BAQsFADAcMRowGAYDVQQDDBFjaTAtY2xpZW50LTItc2FtbDAeFw0yMjEyMjAwNzQxMDhaFw0zMjEyMjAwNzQyNDhaMBwxGjAYBgNVBAMMEWNpMC1jbGllbnQtMi1zYW1sMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlesr4gfXMnlmFW8GCojwFI8n/0bgXTQp3NUbwKjRIpfmjCHtOQBo1whyd4iQdYpJIo+tJZe/lXppQapkyQH7VGYgTE+3/khwq5TzmNuhP93kTSZNrMPDvmYJMOstCLp8iWkOXWwqnGUVavJV5bWP7Xzbyl1PklCUw82w9uMBv2JsARTVMTI+ZW2AHMPIoyiilYD6ezhiQowAp03oYGci0KlXGvdIeb9YRHxNaJs4psnGWVXplp+FZYpvGxbwjw76PNcbNrMCIBx5ZrSHj1Mmh2FvR4ZIKULWrpaWRbubnEvwCje7lPoPPQqXA5rJw/ZU64vndtyFmsjsDEfQDSSR5QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAeMb1osWpULmXYXlf/z7el7EGpwTZA0kknehokJvqYMZDqyoWvbrLuFgkZmb74Sh0zt1Igs8azwvhX1as6Ojb/LZeFIJY8eEKSKhA6XbFvi+NvHPPuLWZNblhioLNoI0DhdwbCf6WrNQfN071dzmUh49xB8x7qQ8vkoAFp83iyN6PqhR7yYbI1UQhonNMSuFFwcoC1dTlsOiS4wZz6sdtq0yTJsL9w6rvATSx1/cJuqHFVlpWb4NHRZpUVFwr7DFc0K7uHqV2VtNKbTFb4ZCxiyxjk1LQRTFidDOR3GnQiMvXnOeEno2Zax2urkC+2+26WPzKkwZPGkqz0B157t/rV","saml.signature.algorithm":"RSA_SHA256","saml_force_name_id_format":"false","saml.client.signature":"true","saml.authnstatement":"true","saml.assertion.lifespan":"120","saml.signing.private.key":"MIIEowIBAAKCAQEAlesr4gfXMnlmFW8GCojwFI8n/0bgXTQp3NUbwKjRIpfmjCHtOQBo1whyd4iQdYpJIo+tJZe/lXppQapkyQH7VGYgTE+3/khwq5TzmNuhP93kTSZNrMPDvmYJMOstCLp8iWkOXWwqnGUVavJV5bWP7Xzbyl1PklCUw82w9uMBv2JsARTVMTI+ZW2AHMPIoyiilYD6ezhiQowAp03oYGci0KlXGvdIeb9YRHxNaJs4psnGWVXplp+FZYpvGxbwjw76PNcbNrMCIBx5ZrSHj1Mmh2FvR4ZIKULWrpaWRbubnEvwCje7lPoPPQqXA5rJw/ZU64vndtyFmsjsDEfQDSSR5QIDAQABAoIBAAUHwg4wgyj/Z8x6UDKUS7H057uqDicyc+EkCW1afMHzZNn43XPXLq1gbC7UlzxKao/NUFr9j4EdfWClrgIMnflD//tvhVXz6kvnkJDldbCl6l4oVdzhKLU/yTkp+vXbBAi8TK4Xzgo3XhOblAREJlMqqFlO7jeTmppDUZfHICzivGTM0eJEeb3eMhMwro0DJ6J1nzaXB3456n96aUcTwEYf7pGE2fc0yUonyBGMALDHaFThTfOKGSw7817enkTWrRSdvwb2/vcfRrxdfttciKj9H4f5d19OiGBTSKUfpluh5s8Mg8HkTskMO4UGrGppCzl8f3twRG8QI2rSEwUypBUCgYEAx6MxCtDOflgT+JpWKcyNuOZ5oJ+E7wQXiMyTC6AT6Ivqp9MC8oFySXUDIluBecdcPqqtrQllXKqwP5clODMKcPb4+ejBQ0yHIng/4A5bhPP8SyUeJqVEpS1f4GxKVFSEPMguIBoKvmmcdAD4MiCe/wdVAW0xROVCRotQE/DV8csCgYEAwD6Mg9FjZl8U2aeX6Ooyhz1+Ik2HM8RnHMVR4gyw5u3B+uY7aPBp3xYhP2LGXRu4X3wsvPov8qyEyCiO+5hT8RUb/SHvqHX00VO2DfeM3+oIwyXmST10oDvAqtvaWLXDdTa1HInx6hrobKv/rJVRUwkmmptzntoDnzjZQI+ZVQ8CgYBY766NbvBPANYEzlzMSkBouuQ8VlRWVrBVVS285Bd6ZbqoAS0y89ACQYqf57wKkHHbyRWOHL13RuM1sRP3sWVZZe0NCE/wt0sMZB2wpzTGSht/Lo38EWw/WbN4u0VxxCUVHujNjEx0/3+ffj8TtcyfOJj6BbcJRkj8PFv0RjpJeQKBgAmUlGgVTUDSyDU4ludylGYM+HY5Kt23kfPrGXOMclxvyNT6GEfYg04syidggsYtFXkctRYN2cncMxnOe6GqK7S9+pEY2dqpVjQAWfhEN+8IuLsQ7nMD7wX1NFrPbggxtrXmrgvoC/hAswiHYcx1/IGI2TWnPZHTB48txBXlkhydAoGBALxl/32La2ZlpbsSdQ/c+J5BDctm/Z0wxn4pdG+Qg7+tjTEAof3Mpvc1AjqABEMPWunWDyIncqXQkFiEOj2mEYuUFnZM5DOGaEMybArNu9oqLoDQir/8/IAVxBcrlR3lY3+OOuTZTGHvjKiApIvv5HUmdCNZXcXAskQCr3XzmRDB","saml_name_id_format":"username","saml_signature_canonicalization_method":"http://www.w3.org/2001/10/xml-exc-c14n#"},"authenticationFlowBindingOverrides":{"browser":"e04769fe-3086-4b6c-978d-806570c69d3e"},"fullScopeAllowed":false,"nodeReRegistrationTimeout":-1,"protocolMappers":[{"id":"e1eb60f8-bdd1-4402-b10f-0efb8bb6f56a","name":"X500 email","protocol":"saml","protocolMapper":"saml-user-property-mapper","consentRequired":false,"config":{"attribute.nameformat":"urn:oasis:names:tc:SAML:2.0:attrname-format:uri","user.attribute":"email","friendly.name":"email","attribute.name":"urn:oid:1.2.840.113549.1.9.1"}},{"id":"50df2901-e540-4ba5-a13c-bf01f41989e7","name":"ci0-client-2-saml-mapper-js","protocol":"saml","protocolMapper":"saml-javascript-mapper","consentRequired":false,"config":{"single":"true","Script":"/**/\n//insert your code here...","attribute.nameformat":"Basic","friendly.name":"ci0-client-2-saml-mapper-js-friedly","attribute.name":"ci0-client-2-saml-mapper-attr-name"}}],"defaultClientScopes":["web-origins","role_list","profile","ci0-client-scope-2-saml","roles","email"],"optionalClientScopes":["address","phone","offline_access","microprofile-jwt"],"access":{"view":true,"configure":true,"manage":true}}\
    client2 = client_api.findFirst({'key': 'clientId', 'value': client2_client_id})
    client_api.update_rmw(client2['id'], {"fullScopeAllowed": False})
    #
    # GUI: add realm role ci0-role-1a
    # POST https://172.17.0.2:8443/auth/admin/realms/ci0-realm/clients/17033bb3-0430-46d9-8053-88e56ea62d1d/scope-mappings/realm
    # [{"id":"02e28239-cff7-4e7b-90cf-71fa9c82f151","name":"ci0-role-1a","description":"ci0-role-1a-desc","composite":false,"clientRole":false,"containerId":"ci0-realm-OLD"}]
    client2_scope_mappings_realm_api = client_api.get_child(client_api, client2['id'], "scope-mappings/realm")
    client2_scope_mappings_realm_api.create([ci0_role1a])
    #
    # GUI: add client=account role=manage-account-links
    # POST: https://172.17.0.2:8443/auth/admin/realms/ci0-realm/clients/17033bb3-0430-46d9-8053-88e56ea62d1d/scope-mappings/clients/e5932927-79d4-407f-8891-9a5613ef4ca0
    # [{"id":"3eba80ed-c969-4b71-9d38-95b147430971","name":"manage-account-links","description":"${role_manage-account-links}","composite":false,"clientRole":true,"containerId":"e5932927-79d4-407f-8891-9a5613ef4ca0"}]
    #client2_scope_mappings_clients_api
    client2_scope_mappings_client_api = client_api.get_child(client_api, client2['id'], f"scope-mappings/clients/{client0['id']}")
    client2_scope_mappings_client_api.create([client0_role1])

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
    assert_realm_authentication(master_realm_api, realm_name)

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
    assert_realm_authentication(master_realm_api, realm_name)

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
    assert_realm_authentication(master_realm_api, realm_name)

    client_scopes_api = kc.build('client-scopes', realm_name)
    default_default_client_scopes_api = kc.build('default-default-client-scopes', realm_name)
    default_optional_client_scopes_api = kc.build('default-optional-client-scopes', realm_name)
    if not client_scopes_api.findFirst({'key': 'name', 'value': client_scope_0_name}):
        cs_creation_state = client_scopes_api.create({
            "name": client_scope_0_name,
            "description": "ci0 client scope",
            "protocol": "openid-connect",
            "attributes": {
                "consent.screen.text": "consent-text-ci0-scope",
                "display.on.consent.screen": "true",
                "include.in.token.scope": "true"
            }
        }).isOk()
        client_scope_0 = client_scopes_api.findFirst({'key': 'name', 'value': client_scope_0_name})

        # Assign scope mapping to client scope - set realm role
        client_scope_0_scope_mappings_realm = kc.build(f"client-scopes/{client_scope_0['id']}/scope-mappings/realm", realm_name)
        client_scope_0_scope_mappings_realm.create([ci0_role0])

        # Assign scope mapping to client scope - set client role
        # Just assign some existing client role, view-profile role from client account.
        client_clientId = 'account'
        role_name = "view-profile"
        kc_clients = kc.build(f"clients", realm_name)
        client = kc_clients.findFirst({'key': 'clientId', 'value': client_clientId})
        print(f"client={client}")
        kc_client_roles = kc.build(f"clients/{client['id']}/roles", realm_name)
        role = kc_client_roles.findFirst({'key': 'name', 'value': role_name})
        client_scope_0_scope_mappings_client = kc.build(f"client-scopes/{client_scope_0['id']}/scope-mappings/clients/{client['id']}", realm_name)
        client_scope_0_scope_mappings_client.create([role])

        # Assign mapper to client scope
        client_scope_0_protocol_mapper_many = kc.build(f"client-scopes/{client_scope_0['id']}/protocol-mappers/add-models", realm_name)
        # assign one pre-defined mapper
        client_scope_0_protocol_mapper_many.create([
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
        # client_scope_0_protocol_mapper_single = kc.build(f"client-scopes/{client_scope_id}/protocol-mappers/models", realm_name)

        # make client_scope_id a default client scope - of realm
        # PUT https://172.17.0.2:8443/auth/admin/realms/ci0-realm/default-default-client-scopes/1221f9ec-48ae-450f-8002-5df70916e166
        state = default_default_client_scopes_api.update(
            client_scope_0["id"],
            {
                "realm": realm_name,
                "clientScopeId": client_scope_0['id'],
            },
        ).isOk()

        # make client_scope_id a default client scope - of client0
        state = client_api.update(
            f"{client0['id']}/default-client-scopes/{client_scope_0['id']}",
            {
                "realm": realm_name,
                "client": client0['id'],
                "clientScopeId": client_scope_0['id'],
            },
        ).isOk()
    assert_realm_authentication(master_realm_api, realm_name)

        # TODO what are optional client scopes?

        # TODO client scope has assigned realm and/or client roles, and client uses client scope. Create a circular dependency.

    # a second client scope, type SAML
    if not client_scopes_api.findFirst({'key': 'name', 'value': client_scope_1_name}):
        cs_creation_state = client_scopes_api.create({
            "name": client_scope_1_name,
            "description": "ci0-client-scope-1-saml-desc",
            "protocol": "saml",
            "attributes": {
                "consent.screen.text": "ci0-client-scope-1-saml-consent-text",
                "display.on.consent.screen": "true",
                "include.in.token.scope": "true"
            },
        }).isOk()
        client_scope_1 = client_scopes_api.findFirst({'key': 'name', 'value': client_scope_1_name})

        # make client_scope_id a default optional client scope - of realm
        # PUT https://172.17.0.2:8443/auth/admin/realms/ci0-realm/default-default-client-scopes/1221f9ec-48ae-450f-8002-5df70916e166
        state = default_optional_client_scopes_api.update(
            client_scope_1["id"],
            {
                "realm": realm_name,
                "clientScopeId": client_scope_1['id'],
            },
        ).isOk()
    client_scope_1 = client_scopes_api.findFirst({'key': 'name', 'value': client_scope_1_name})
    assert_realm_authentication(master_realm_api, realm_name)

    # client-scope-2, type SAML, it will be assigned to SAML client
    if not client_scopes_api.findFirst({'key': 'name', 'value': client_scope_2_name}):
        cs_creation_state = client_scopes_api.create({
            "name": client_scope_2_name,
            "description": f"{client_scope_2_name}-desc",
            "protocol": "saml",
            "attributes": {
                "consent.screen.text": "consent-text-ci0-scope-2-saml",
                "display.on.consent.screen": "true",
                "include.in.token.scope": "true"
            }
        }).isOk()
        client_scope_2 = client_scopes_api.findFirst({'key': 'name', 'value': client_scope_2_name})

        # make client_scope_id a default client scope - of client2-saml
        state = client_api.update(
            f"{client2['id']}/default-client-scopes/{client_scope_2['id']}",
            {
                "realm": realm_name,
                "client": client2['id'],
                "clientScopeId": client_scope_2['id'],
            },
        ).isOk()
    client_scope_2 = client_scopes_api.findFirst({'key': 'name', 'value': client_scope_2_name})

    # TODO add identity-provider
    idp_alias = "ci0-ipd-saml"
    idp_display_name = "CI0 User Fedaration - LDAP"
    # Redirect URI - https://172.17.0.2:8443/auth/realms/ci0-realm/broker/saml/endpoint
    # Service Provider Entity ID - https://172.17.0.2:8443/auth/realms/ci0-realm
    # Single Sign-On Service URL - https://172.17.0.3:443/ - should be some other container

    uf0_name = "ci0-uf0-ldap"
    uf1_name = "ci0-uf1-ldap"
    # Adding kerberos user federation has side effect on authentication.
    # Browser flow, 'authenticator': 'auth-spnego' requirement changed
    # from DISABLED to ALTERNATIVE.
    uf2_name = "ci0-uf2-kerberos"
    uf3_name = "ci0-uf3-kerberos"
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
        "parentId": ci0_realm["id"],  # "ci0-realm-OLD",
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
        "providerType": "org.keycloak.storage.UserStorageProvider",
        "parentId": ci0_realm["id"],  # "ci0-realm-OLD",
    }
    # ci0-uf3-kerberos has non-default configuration
    uf2_payload = {
        "name": uf2_name,
        "providerId": "kerberos",
        "providerType": "org.keycloak.storage.UserStorageProvider",
        "parentId": ci0_realm["id"],  # "ci0-realm-OLD",
        "config": {
            "priority": ["2"],
            "enabled": ["true"],
            "cachePolicy": ["EVICT_DAILY"],
            "evictionDay": [],
            "evictionHour": ["1"],
            "evictionMinute": ["2"],
            "maxLifespan": [],
            "kerberosRealm": ["ci0-kerberos-realm"],
            "serverPrincipal": ["ci0-server-pricinpal"],
            "keyTab": ["/etc/ci0-keytab"],
            "debug": ["true"],
            "allowPasswordAuthentication": ["true"],
            "editMode": ["READ_ONLY"],
            "updateProfileFirstLogin": ["true"],
        },
    }
    # ci0-uf3-kerberos has default configuration
    uf3_payload = {
        "name": uf3_name,
        "providerId": "kerberos",
        "providerType": "org.keycloak.storage.UserStorageProvider",
        "parentId": ci0_realm["id"],  # "ci0-realm-OLD",
        "config": {
            "priority": ["0"],
            "enabled": ["true"],
            "cachePolicy": ["DEFAULT"],
            "evictionDay": [],
            "evictionHour": [],
            "evictionMinute": [],
            "maxLifespan": [],
            "kerberosRealm": ["aa"],
            "serverPrincipal": ["bb"],
            "keyTab": ["cc"],
            "debug": ["false"],
            "allowPasswordAuthentication": ["false"],
            "editMode": [],
            "updateProfileFirstLogin": ["false"],
        },
    }
    components_api = kc.build(f"components", realm_name)
    # ---------------------------------------------------------------------------------------------------------
    if not components_api.findFirstByKV("name", uf0_name):
        components_api.create(uf0_payload)
        # TODO add additional mapper to user-federation
        # POST https://172.17.0.2:8443/auth/admin/realms/ci0-realm/components
        # {"config":{"user.model.attribute":["ci-user-model-attr"],"ldap.attribute":["ci-ldap-attr"],"read.only":["true"],"always.read.value.from.ldap":["true"],"is.mandatory.in.ldap":["false"],"is.binary.attribute":["true"]},"name":"ci0-uf0-mapper-0-user-attr","providerId":"user-attribute-ldap-mapper","providerType":"org.keycloak.storage.ldap.mappers.LDAPStorageMapper","parentId":"3a909e4d-d805-463b-90ee-c95cd07c7f45"}
        uf0 = components_api.findFirstByKV("name", uf0_name)
        components_api.create({
            "config": {
                "user.model.attribute": ["ci-user-model-attr"],
                "ldap.attribute": ["ci-ldap-attr"],
                "read.only": ["true"],
                "always.read.value.from.ldap": ["true"],
                "is.mandatory.in.ldap": ["false"],
                "is.binary.attribute": ["true"],
            },
            "name": "ci0-uf0-mapper-0-user-attr", "providerId": "user-attribute-ldap-mapper",
            "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
            "parentId": uf0["id"],
        })
    # ---------------------------------------------------------------------------------------------------------
    if not components_api.findFirstByKV("name", uf1_name):
        components_api.create(uf1_payload)
    # ---------------------------------------------------------------------------------------------------------
    # POST https://172.17.0.2:8443/auth/admin/realms/ci0-realm/components
    # {"name":"kerberos","providerId":"kerberos","providerType":"org.keycloak.storage.UserStorageProvider","parentId":"ci0-realm-OLD","config":{"priority":["2"],"enabled":["true"],"cachePolicy":["EVICT_DAILY"],"evictionDay":[],"evictionHour":["1"],"evictionMinute":["2"],"maxLifespan":[],"kerberosRealm":["ci0-kerberos-realm"],"serverPrincipal":["ci0-server-pricinpal"],"keyTab":["/etc/ci0-keytab"],"debug":["true"],"allowPasswordAuthentication":["true"],"editMode":["READ_ONLY"],"updateProfileFirstLogin":["true"]}}
    if not components_api.findFirstByKV("name", uf2_name):
        components_api.create(uf2_payload)
    if not components_api.findFirstByKV("name", uf3_name):
        components_api.create(uf3_payload)
    assert_realm_authentication(master_realm_api, realm_name)

    # configure events
    events_config_api = kc.build('events/config', realm_name)
    # PUT https://172.17.0.2:8443/auth/admin/realms/ci0-realm/events/config
    # {"eventsEnabled":false,"eventsListeners":["jboss-logging","ci0-event-0"],"enabledEventTypes":["LOGIN","LOGIN_ERROR","REGISTER","REGISTER_ERROR","LOGOUT","LOGOUT_ERROR","CODE_TO_TOKEN","CODE_TO_TOKEN_ERROR","CLIENT_LOGIN","CLIENT_LOGIN_ERROR","FEDERATED_IDENTITY_LINK","FEDERATED_IDENTITY_LINK_ERROR","REMOVE_FEDERATED_IDENTITY","REMOVE_FEDERATED_IDENTITY_ERROR","UPDATE_EMAIL","UPDATE_EMAIL_ERROR","UPDATE_PROFILE","UPDATE_PROFILE_ERROR","UPDATE_PASSWORD","UPDATE_PASSWORD_ERROR","UPDATE_TOTP","UPDATE_TOTP_ERROR","VERIFY_EMAIL","VERIFY_EMAIL_ERROR","REMOVE_TOTP","REMOVE_TOTP_ERROR","GRANT_CONSENT","GRANT_CONSENT_ERROR","UPDATE_CONSENT","UPDATE_CONSENT_ERROR","REVOKE_GRANT","REVOKE_GRANT_ERROR","SEND_VERIFY_EMAIL","SEND_VERIFY_EMAIL_ERROR","SEND_RESET_PASSWORD","SEND_RESET_PASSWORD_ERROR","SEND_IDENTITY_PROVIDER_LINK","SEND_IDENTITY_PROVIDER_LINK_ERROR","RESET_PASSWORD","RESET_PASSWORD_ERROR","RESTART_AUTHENTICATION","RESTART_AUTHENTICATION_ERROR","IDENTITY_PROVIDER_LINK_ACCOUNT","IDENTITY_PROVIDER_LINK_ACCOUNT_ERROR","IDENTITY_PROVIDER_FIRST_LOGIN","IDENTITY_PROVIDER_FIRST_LOGIN_ERROR","IDENTITY_PROVIDER_POST_LOGIN","IDENTITY_PROVIDER_POST_LOGIN_ERROR","IMPERSONATE","IMPERSONATE_ERROR","CUSTOM_REQUIRED_ACTION","CUSTOM_REQUIRED_ACTION_ERROR","EXECUTE_ACTIONS","EXECUTE_ACTIONS_ERROR","EXECUTE_ACTION_TOKEN","EXECUTE_ACTION_TOKEN_ERROR","CLIENT_REGISTER","CLIENT_REGISTER_ERROR","CLIENT_UPDATE","CLIENT_UPDATE_ERROR","CLIENT_DELETE","CLIENT_DELETE_ERROR","CLIENT_INITIATED_ACCOUNT_LINKING","CLIENT_INITIATED_ACCOUNT_LINKING_ERROR","TOKEN_EXCHANGE","TOKEN_EXCHANGE_ERROR","PERMISSION_TOKEN"],"adminEventsEnabled":false,"adminEventsDetailsEnabled":false,"eventsExpiration":null}
    # {"eventsEnabled":true,"eventsListeners":["jboss-logging","email"],       "enabledEventTypes":["SEND_RESET_PASSWORD","UPDATE_CONSENT_ERROR","GRANT_CONSENT","REMOVE_TOTP","REVOKE_GRANT","UPDATE_TOTP","LOGIN_ERROR","CLIENT_LOGIN","RESET_PASSWORD_ERROR","IMPERSONATE_ERROR","CODE_TO_TOKEN_ERROR","CUSTOM_REQUIRED_ACTION","RESTART_AUTHENTICATION","IMPERSONATE","UPDATE_PROFILE_ERROR","LOGIN","UPDATE_PASSWORD_ERROR","CLIENT_INITIATED_ACCOUNT_LINKING","TOKEN_EXCHANGE","LOGOUT","REGISTER","CLIENT_REGISTER","IDENTITY_PROVIDER_LINK_ACCOUNT","UPDATE_PASSWORD","CLIENT_DELETE","FEDERATED_IDENTITY_LINK_ERROR","IDENTITY_PROVIDER_FIRST_LOGIN","CLIENT_DELETE_ERROR","VERIFY_EMAIL","CLIENT_LOGIN_ERROR","RESTART_AUTHENTICATION_ERROR","EXECUTE_ACTIONS","REMOVE_FEDERATED_IDENTITY_ERROR","TOKEN_EXCHANGE_ERROR","PERMISSION_TOKEN","SEND_IDENTITY_PROVIDER_LINK_ERROR","EXECUTE_ACTION_TOKEN_ERROR","SEND_VERIFY_EMAIL","EXECUTE_ACTIONS_ERROR","REMOVE_FEDERATED_IDENTITY","IDENTITY_PROVIDER_POST_LOGIN","IDENTITY_PROVIDER_LINK_ACCOUNT_ERROR","UPDATE_EMAIL","REGISTER_ERROR","REVOKE_GRANT_ERROR","EXECUTE_ACTION_TOKEN","LOGOUT_ERROR","UPDATE_EMAIL_ERROR","CLIENT_UPDATE_ERROR","UPDATE_PROFILE","CLIENT_REGISTER_ERROR","FEDERATED_IDENTITY_LINK","SEND_IDENTITY_PROVIDER_LINK","SEND_VERIFY_EMAIL_ERROR","RESET_PASSWORD","CLIENT_INITIATED_ACCOUNT_LINKING_ERROR","UPDATE_CONSENT","REMOVE_TOTP_ERROR","VERIFY_EMAIL_ERROR","SEND_RESET_PASSWORD_ERROR","CLIENT_UPDATE","CUSTOM_REQUIRED_ACTION_ERROR","IDENTITY_PROVIDER_POST_LOGIN_ERROR","UPDATE_TOTP_ERROR","CODE_TO_TOKEN","GRANT_CONSENT_ERROR"],"adminEventsEnabled":false,"adminEventsDetailsEnabled":false,"eventsExpiration":0}
    # {"eventsEnabled":true,"eventsListeners":["jboss-logging","email"],"enabledEventTypes":["SEND_RESET_PASSWORD","UPDATE_CONSENT_ERROR","GRANT_CONSENT","REMOVE_TOTP","REVOKE_GRANT","UPDATE_TOTP","LOGIN_ERROR","CLIENT_LOGIN","RESET_PASSWORD_ERROR","IMPERSONATE_ERROR","CODE_TO_TOKEN_ERROR","CUSTOM_REQUIRED_ACTION","RESTART_AUTHENTICATION","IMPERSONATE","UPDATE_PROFILE_ERROR","LOGIN","UPDATE_PASSWORD_ERROR","CLIENT_INITIATED_ACCOUNT_LINKING","TOKEN_EXCHANGE","LOGOUT","REGISTER","CLIENT_REGISTER","IDENTITY_PROVIDER_LINK_ACCOUNT","UPDATE_PASSWORD","CLIENT_DELETE","FEDERATED_IDENTITY_LINK_ERROR","IDENTITY_PROVIDER_FIRST_LOGIN","CLIENT_DELETE_ERROR","VERIFY_EMAIL","CLIENT_LOGIN_ERROR","RESTART_AUTHENTICATION_ERROR","EXECUTE_ACTIONS","REMOVE_FEDERATED_IDENTITY_ERROR","TOKEN_EXCHANGE_ERROR","PERMISSION_TOKEN","SEND_IDENTITY_PROVIDER_LINK_ERROR","EXECUTE_ACTION_TOKEN_ERROR","SEND_VERIFY_EMAIL","EXECUTE_ACTIONS_ERROR","REMOVE_FEDERATED_IDENTITY","IDENTITY_PROVIDER_POST_LOGIN","IDENTITY_PROVIDER_LINK_ACCOUNT_ERROR","UPDATE_EMAIL","REGISTER_ERROR","REVOKE_GRANT_ERROR","EXECUTE_ACTION_TOKEN","LOGOUT_ERROR","UPDATE_EMAIL_ERROR","CLIENT_UPDATE_ERROR","UPDATE_PROFILE","CLIENT_REGISTER_ERROR","FEDERATED_IDENTITY_LINK","SEND_IDENTITY_PROVIDER_LINK","SEND_VERIFY_EMAIL_ERROR","RESET_PASSWORD","CLIENT_INITIATED_ACCOUNT_LINKING_ERROR","UPDATE_CONSENT","REMOVE_TOTP_ERROR","VERIFY_EMAIL_ERROR","SEND_RESET_PASSWORD_ERROR","CLIENT_UPDATE","CUSTOM_REQUIRED_ACTION_ERROR","IDENTITY_PROVIDER_POST_LOGIN_ERROR","UPDATE_TOTP_ERROR","CODE_TO_TOKEN","GRANT_CONSENT_ERROR"],"adminEventsEnabled":true,"adminEventsDetailsEnabled":true,"eventsExpiration":435600}
    events_config_old = events_config_api.get(None).verify().resp().json()
    events_config_data = copy(events_config_old)
    if "email" not in events_config_data["eventsListeners"]:
        events_config_data["eventsListeners"] = ["jboss-logging", "email"]
        events_config_data["enabledEventTypes"].remove("CLIENT_INITIATED_ACCOUNT_LINKING_ERROR")
        events_config_data.update({
            "eventsEnabled": True,
            "adminEventsEnabled": True,
            "adminEventsDetailsEnabled": True,
            "eventsExpiration": 3600,
        })
        events_config_api.update(None, events_config_data)
    events_config_new = events_config_api.get(None).verify().resp().json()
    assert "email" in events_config_new["eventsListeners"]
    assert "CLIENT_INITIATED_ACCOUNT_LINKING_ERROR" not in events_config_new["enabledEventTypes"]
    assert_realm_authentication(master_realm_api, realm_name)


def assert_realm_authentication(master_realm_api, realm_name):
    realm_data_old2 = master_realm_api.get(realm_name).verify().resp().json()
    assert realm_data_old2["resetCredentialsFlow"] == "ci0-auth-flow-generic"
    assert realm_data_old2["passwordPolicy"] == "forceExpiredPasswordChange(365) and upperCase(2)"
    assert realm_data_old2["otpPolicyType"] == "hotp"
    assert realm_data_old2["webAuthnPolicyRpId"] == "ci0.example.com"
    assert realm_data_old2["webAuthnPolicyPasswordlessRpId"] == "ci0-RpId"
    # webAuthnPolicyAttestationConveyancePreference and webAuthnPolicyPasswordlessAttestationConveyancePreference
    # were not set with single update call
    assert realm_data_old2["webAuthnPolicyAttestationConveyancePreference"] == "indirect"
    assert realm_data_old2["webAuthnPolicyPasswordlessAttestationConveyancePreference"] == "none"
    # Surprise v2 - at line 990, reevaluate "realm_data_old2 = master_realm_api.get(realm_name).verify().resp().json()"
    # line 990: "if not components_api.findFirst({'key': 'name', 'value': uf0_name}):"
    # And webAuthnPolicyAttestationConveyancePreference are different.


if __name__ == "__main__":
    main()

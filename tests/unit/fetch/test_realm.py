from copy import copy

from pytest import mark
from pytest_unordered import unordered
import json
import os
from path import glob
from kcfetcher.fetch import RealmFetch
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login, RH_SSO_VERSIONS_7_4, RH_SSO_VERSIONS_7_5


@mark.vcr()
class TestRealmFetch_vcr:
    def test__get_data(self):
        datadir = "output/ci/outd"
        remove_folder(datadir)
        make_folder(datadir)
        store_api = Store(datadir)
        server = os.environ["SSO_API_URL"]
        user = os.environ["SSO_API_USERNAME"]
        password = os.environ["SSO_API_PASSWORD"]
        kc = login(server, user, password)

        # Do what main.py does.
        realms_api = kc.admin()
        # for realm in realms_api.all():
        #     current_realm = realm['realm']
        #     store = Store(path=datadir)
        #     store.add_child(current_realm)
        #     store.store_one(realm, 'realm')

        store = Store(path=datadir)
        realm_fetcher = RealmFetch(kc)
        for realm in realms_api.all():
            realm_name = realm['realm']
            store.add_child(realm_name)  # outd/<realm>
            realm_fetcher.fetch_one(store, realm)
            store.remove_last_child()  # outd/<realm>

        # check generated content
        assert unordered(glob.glob('**', root_dir=datadir, recursive=True)) == [
            'master',
            'master/master.json',
            'ci0-realm',
            'ci0-realm/ci0-realm.json'
        ]

        expected_realm_attrs = [
            'accessCodeLifespan',
            'accessCodeLifespanLogin',
            'accessCodeLifespanUserAction',
            'accessTokenLifespan',
            'accessTokenLifespanForImplicitFlow',
            'actionTokenGeneratedByAdminLifespan',
            'actionTokenGeneratedByUserLifespan',
            'adminEventsDetailsEnabled',
            'adminEventsEnabled',
            'attributes',
            'browserFlow',
            'browserSecurityHeaders',
            'bruteForceProtected',
            'clientAuthenticationFlow',
            # not in RH 7.4
            # 'clientOfflineSessionIdleTimeout',
            # 'clientOfflineSessionMaxLifespan',
            # 'clientPolicies',
            # 'clientProfiles',
            # 'clientSessionIdleTimeout',
            # 'clientSessionMaxLifespan',

            # 'defaultRole', # RH 7.5
            'defaultRoles', # RH 7.4

            # 'defaultSignatureAlgorithm',
            'directGrantFlow',
            'displayName',
            'displayNameHtml',
            'dockerAuthenticationFlow',
            'duplicateEmailsAllowed',
            'editUsernameAllowed',
            'enabled',
            'enabledEventTypes',
            'eventsEnabled',
            'eventsExpiration',
            'eventsListeners',
            'failureFactor',
            # 'identityProviderMappers',  # is intentionally removed
            # 'identityProviders',  # is intentionally removed
            'internationalizationEnabled',
            'loginWithEmailAllowed',
            'maxDeltaTimeSeconds',
            'maxFailureWaitSeconds',
            'minimumQuickLoginWaitSeconds',
            'notBefore',
            # 'oauth2DeviceCodeLifespan',
            # 'oauth2DevicePollingInterval',
            'offlineSessionIdleTimeout',
            'offlineSessionMaxLifespan',
            'offlineSessionMaxLifespanEnabled',
            'otpPolicyAlgorithm',
            'otpPolicyDigits',
            'otpPolicyInitialCounter',
            'otpPolicyLookAheadWindow',
            'otpPolicyPeriod',
            'otpPolicyType',
            'otpSupportedApplications',
            'permanentLockout',
            'quickLoginCheckMilliSeconds',
            'realm',
            'refreshTokenMaxReuse',
            'registrationAllowed',
            'registrationEmailAsUsername',
            'registrationFlow',
            'rememberMe',
            'requiredCredentials',
            'resetCredentialsFlow',
            'resetPasswordAllowed',
            'revokeRefreshToken',
            'smtpServer',
            'sslRequired',
            'ssoSessionIdleTimeout',
            'ssoSessionIdleTimeoutRememberMe',
            'ssoSessionMaxLifespan',
            'ssoSessionMaxLifespanRememberMe',
            'supportedLocales',
            'userManagedAccessAllowed',
            'verifyEmail',
            'waitIncrementSeconds',
            'webAuthnPolicyAcceptableAaguids',
            'webAuthnPolicyAttestationConveyancePreference',
            'webAuthnPolicyAuthenticatorAttachment',
            'webAuthnPolicyAvoidSameAuthenticatorRegister',
            'webAuthnPolicyCreateTimeout',
            'webAuthnPolicyPasswordlessAcceptableAaguids',
            'webAuthnPolicyPasswordlessAttestationConveyancePreference',
            'webAuthnPolicyPasswordlessAuthenticatorAttachment',
            'webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister',
            'webAuthnPolicyPasswordlessCreateTimeout',
            'webAuthnPolicyPasswordlessRequireResidentKey',
            'webAuthnPolicyPasswordlessRpEntityName',
            'webAuthnPolicyPasswordlessRpId',
            'webAuthnPolicyPasswordlessSignatureAlgorithms',
            'webAuthnPolicyPasswordlessUserVerificationRequirement',
            'webAuthnPolicyRequireResidentKey',
            'webAuthnPolicyRpEntityName',
            'webAuthnPolicyRpId',
            'webAuthnPolicySignatureAlgorithms',
            'webAuthnPolicyUserVerificationRequirement',
        ]
        if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_5:
            # TODO v7.4 - is this actually missing, or in different place?
            expected_realm_attrs.remove("defaultRoles")
            expected_realm_attrs.extend([
                'clientOfflineSessionIdleTimeout',
                'clientOfflineSessionMaxLifespan',
                'clientPolicies',
                'clientProfiles',
                'clientSessionIdleTimeout',
                'clientSessionMaxLifespan',
                'defaultRole', # RH 7.5
                'defaultSignatureAlgorithm',
                'oauth2DeviceCodeLifespan',
                'oauth2DevicePollingInterval',
            ])
        # password policy is configured for ci0-realm, but not for master realm
        expected_realm_attrs___ci0_realm = [
            "passwordPolicy",
        ]

        data = json.load(open(os.path.join(datadir, "ci0-realm/ci0-realm.json")))
        assert list(data.keys()) == unordered(expected_realm_attrs + expected_realm_attrs___ci0_realm)
        assert data["realm"] == "ci0-realm"
        assert data["displayName"] == "ci0-realm-display"
        # and a few attributes that are not setup by inject_data.py
        assert data["internationalizationEnabled"] == False
        assert data["clientAuthenticationFlow"] == "clients"

        # identity provider - mappers are part of /realms/ API endpoint
        # Check we have correct content
        assert "identityProviderMappers" not in data

        if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_4:
            assert data["defaultRoles"] == [
                "ci0-role-0",
                "offline_access",
                "uma_authorization",
            ]
        else:
            assert kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_5
            assert data["defaultRole"] == {
                'clientRole': False,
                'composite': True,
                'containerId': 'ci0-realm-OLD',
                'description': '${role_default-roles}',
                'name': 'default-roles-ci0-realm-old',
            }

        # Check Events Config is correctly stored
        assert data["adminEventsDetailsEnabled"] is True
        assert data["adminEventsEnabled"] is True
        assert data["eventsEnabled"] is True
        assert data["eventsExpiration"] == 3600
        assert data["eventsListeners"] == [
            "jboss-logging",
            "email"
        ]
        expected_enabledEventTypes = [
            "SEND_RESET_PASSWORD",
            "UPDATE_CONSENT_ERROR",
            "GRANT_CONSENT",
            "REMOVE_TOTP",
            "REVOKE_GRANT",
            "UPDATE_TOTP",
            "LOGIN_ERROR",
            "CLIENT_LOGIN",
            "RESET_PASSWORD_ERROR",
            "IMPERSONATE_ERROR",
            "CODE_TO_TOKEN_ERROR",
            "CUSTOM_REQUIRED_ACTION",
            "RESTART_AUTHENTICATION",
            "IMPERSONATE",
            "UPDATE_PROFILE_ERROR",
            "LOGIN",
            "UPDATE_PASSWORD_ERROR",
            "CLIENT_INITIATED_ACCOUNT_LINKING",
            "TOKEN_EXCHANGE",
            "LOGOUT",
            "REGISTER",
            "CLIENT_REGISTER",
            "IDENTITY_PROVIDER_LINK_ACCOUNT",
            "UPDATE_PASSWORD",
            "CLIENT_DELETE",
            "FEDERATED_IDENTITY_LINK_ERROR",
            "IDENTITY_PROVIDER_FIRST_LOGIN",
            "CLIENT_DELETE_ERROR",
            "VERIFY_EMAIL",
            "CLIENT_LOGIN_ERROR",
            "RESTART_AUTHENTICATION_ERROR",
            "EXECUTE_ACTIONS",
            "REMOVE_FEDERATED_IDENTITY_ERROR",
            "TOKEN_EXCHANGE_ERROR",
            "PERMISSION_TOKEN",
            "SEND_IDENTITY_PROVIDER_LINK_ERROR",
            "EXECUTE_ACTION_TOKEN_ERROR",
            "SEND_VERIFY_EMAIL",
            "EXECUTE_ACTIONS_ERROR",
            "REMOVE_FEDERATED_IDENTITY",
            "IDENTITY_PROVIDER_POST_LOGIN",
            "IDENTITY_PROVIDER_LINK_ACCOUNT_ERROR",
            "UPDATE_EMAIL",
            "REGISTER_ERROR",
            "REVOKE_GRANT_ERROR",
            "EXECUTE_ACTION_TOKEN",
            "LOGOUT_ERROR",
            "UPDATE_EMAIL_ERROR",
            "CLIENT_UPDATE_ERROR",
            "UPDATE_PROFILE",
            "CLIENT_REGISTER_ERROR",
            "FEDERATED_IDENTITY_LINK",
            "SEND_IDENTITY_PROVIDER_LINK",
            "SEND_VERIFY_EMAIL_ERROR",
            "RESET_PASSWORD",
            "UPDATE_CONSENT",
            "REMOVE_TOTP_ERROR",
            "VERIFY_EMAIL_ERROR",
            "SEND_RESET_PASSWORD_ERROR",
            "CLIENT_UPDATE",
            "CUSTOM_REQUIRED_ACTION_ERROR",
            "IDENTITY_PROVIDER_POST_LOGIN_ERROR",
            "UPDATE_TOTP_ERROR",
            "CODE_TO_TOKEN",
            "GRANT_CONSENT_ERROR",
            "IDENTITY_PROVIDER_FIRST_LOGIN_ERROR",
        ]
        if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_5:
            expected_enabledEventTypes += [
                "VERIFY_PROFILE_ERROR",
                "OAUTH2_DEVICE_CODE_TO_TOKEN_ERROR",
                "OAUTH2_DEVICE_VERIFY_USER_CODE",
                "AUTHREQID_TO_TOKEN",
                "DELETE_ACCOUNT_ERROR",
                "DELETE_ACCOUNT",
                "OAUTH2_DEVICE_AUTH",
                "OAUTH2_DEVICE_CODE_TO_TOKEN",
                "OAUTH2_DEVICE_VERIFY_USER_CODE_ERROR",
                "AUTHREQID_TO_TOKEN_ERROR",
                "OAUTH2_DEVICE_AUTH_ERROR",
                "VERIFY_PROFILE",
            ]
        assert data["enabledEventTypes"] == sorted(expected_enabledEventTypes)

        # ------------------------------------------------------------------
        # Authentication - bindings
        assert data["resetCredentialsFlow"] == "ci0-auth-flow-generic"
        # ------------------------------------------------------------------
        # Authentication - password policy
        assert data["passwordPolicy"] == "forceExpiredPasswordChange(365) and upperCase(2)"
        # ------------------------------------------------------------------
        # Authentication - OTP policy
        assert data["otpPolicyType"] == "hotp"
        assert data["otpPolicyAlgorithm"] == "HmacSHA256"
        assert data["otpPolicyDigits"] == 8
        assert data["otpPolicyInitialCounter"] == 3
        assert data["otpPolicyLookAheadWindow"] == 2
        assert data["otpPolicyPeriod"] == 30
        assert data["otpSupportedApplications"] == [
            "FreeOTP",
        ]
        # ------------------------------------------------------------------
        # Authentication - WebAuthn Policy
        assert data["webAuthnPolicyAttestationConveyancePreference"] == "indirect"
        assert data["webAuthnPolicyAuthenticatorAttachment"] == "platform"
        assert data["webAuthnPolicyAvoidSameAuthenticatorRegister"] == True
        assert data["webAuthnPolicyCreateTimeout"] == 2
        assert data["webAuthnPolicyRequireResidentKey"] == "Yes"
        assert data["webAuthnPolicyRpEntityName"] == "keycloak"
        assert data["webAuthnPolicyRpId"] == "ci0.example.com"
        assert data["webAuthnPolicySignatureAlgorithms"] == [
            "ES384",
            "ES512",
        ]
        assert data["webAuthnPolicyUserVerificationRequirement"] == "required"
        assert data["webAuthnPolicyAcceptableAaguids"] == [
            "ci0-aaguid-0",
        ]
        # ------------------------------------------------------------------
        # Authentication - webAuthnPolicyPasswordless
        assert data["webAuthnPolicyPasswordlessAcceptableAaguids"] == [
            "cio-aaguid-1",
        ]
        assert data["webAuthnPolicyPasswordlessAttestationConveyancePreference"] == "none"
        assert data["webAuthnPolicyPasswordlessAuthenticatorAttachment"] == "platform"
        assert data["webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister"] == True
        assert data["webAuthnPolicyPasswordlessCreateTimeout"] == 4
        assert data["webAuthnPolicyPasswordlessRequireResidentKey"] == "No"
        assert data["webAuthnPolicyPasswordlessRpId"] == "ci0-RpId"
        assert data["webAuthnPolicyPasswordlessSignatureAlgorithms"] == [
            "ES512",
            "RS256",
        ]
        assert data["webAuthnPolicyPasswordlessUserVerificationRequirement"] == "preferred"

        # ci0-realm has modified values
        expected_realm_security_defenses = {
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
        assert_subobj_eq_obj(expected_realm_security_defenses, data)

        # =====================================================================================
        data = json.load(open(os.path.join(datadir, "master/master.json")))
        # identityProviderMappers - if the list would be empty, then:
        # RH SSO 7.4 will not include this into realms.json at all
        # RH SSO 7.5 will include it, identityProviderMappers=[]

        # in master realms we didn't reconfigure events
        expected_realm_attrs_master = copy(expected_realm_attrs)
        expected_realm_attrs_master.remove('eventsExpiration')

        if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_5:
            assert list(data.keys()) == unordered(expected_realm_attrs_master)
        else:
            # RH SSO 7.4
            assert list(data.keys()) == unordered(expected_realm_attrs_master)
            assert data["defaultRoles"] == [
                "offline_access",
                "uma_authorization",
            ]

        # master realm has default values
        expected_realm_security_defenses = {
            "browserSecurityHeaders": {
                "contentSecurityPolicy": "frame-src 'self'; frame-ancestors 'self'; object-src 'none';",
                "contentSecurityPolicyReportOnly": "",
                "strictTransportSecurity": "max-age=31536000; includeSubDomains",
                "xContentTypeOptions": "nosniff",
                "xFrameOptions": "SAMEORIGIN",
                "xRobotsTag": "none",
                "xXSSProtection": "1; mode=block"
            },
            "bruteForceProtected": False,
            "failureFactor": 30,
            "maxDeltaTimeSeconds": 43200,
            "maxFailureWaitSeconds": 900,
            "minimumQuickLoginWaitSeconds": 60,
            "quickLoginCheckMilliSeconds": 1000,
            "waitIncrementSeconds": 60,
        }
        assert_subobj_eq_obj(expected_realm_security_defenses, data)


def assert_subobj_eq_obj(expected_subobj, obj):
    """
    For every key in expected_subobj, check obj has same value.
    """
    for key in expected_subobj:
        assert expected_subobj[key] == obj[key]

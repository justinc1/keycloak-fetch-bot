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
            'eventsListeners',
            'failureFactor',
            'identityProviderMappers',
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

        data = json.load(open(os.path.join(datadir, "ci0-realm/ci0-realm.json")))
        assert list(data.keys()) == unordered(expected_realm_attrs)
        assert data["realm"] == "ci0-realm"
        assert data["displayName"] == "ci0-realm-display"
        # and a few attributes that are not setup by inject_data.py
        assert data["internationalizationEnabled"] == False
        assert data["clientAuthenticationFlow"] == "clients"
        # identity provider - mappers are part of /realms/ API endpoint
        # Check we have correct content
        assert data["identityProviderMappers"] == [
            {
                "config": {
                    "are.attribute.values.regex": "false",
                    "attributes": "[{\"key\":\"key0\",\"value\":\"value0\"}]",
                    "role": "ci0-role-0",
                    "syncMode": "INHERIT"
                },
                "identityProviderAlias": "ci0-idp-saml-0",
                "identityProviderMapper": "saml-advanced-role-idp-mapper",
                "name": "idp-mapper-0b"
            }
        ]
        if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_4:
            assert data["defaultRoles"] == unordered([
                "offline_access",
                "uma_authorization",
                "ci0-role-0",
            ])
        else:
            assert kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_5
            assert data["defaultRole"] == {
                'clientRole': False,
                'composite': True,
                'containerId': 'ci0-realm',
                'description': '${role_default-roles}',
                'name': 'default-roles-ci0-realm',
            }

        # =====================================================================================
        data = json.load(open(os.path.join(datadir, "master/master.json")))
        # identityProviderMappers - if the list would be empty, then:
        # RH SSO 7.4 will not include this into realms.json at all
        # RH SSO 7.5 will include it, identityProviderMappers=[]
        if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_5:
            assert list(data.keys()) == unordered(expected_realm_attrs)
            assert data["identityProviderMappers"] == []
        else:
            # RH SSO 7.4
            # TODO - make this [] in .json file
            expected_realm_attrs.remove("identityProviderMappers")
            assert list(data.keys()) == unordered(expected_realm_attrs)
            assert data["defaultRoles"] == unordered([
                "offline_access",
                "uma_authorization",
            ])

from pytest import mark
from pytest_unordered import unordered
import json
import os
from path import glob
from kcfetcher.fetch import RealmFetch
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login


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

        data = json.load(open(os.path.join(datadir, "ci0-realm/ci0-realm.json")))
        assert list(data.keys()) == [
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
            'clientOfflineSessionIdleTimeout',
            'clientOfflineSessionMaxLifespan',
            'clientPolicies',
            'clientProfiles',
            'clientSessionIdleTimeout',
            'clientSessionMaxLifespan',
            'defaultRole',
            'defaultSignatureAlgorithm',
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
            'identityProviders',
            'internationalizationEnabled',
            'loginWithEmailAllowed',
            'maxDeltaTimeSeconds',
            'maxFailureWaitSeconds',
            'minimumQuickLoginWaitSeconds',
            'notBefore',
            'oauth2DeviceCodeLifespan',
            'oauth2DevicePollingInterval',
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
        assert data["realm"] == "ci0-realm"
        assert data["displayName"] == "ci0-realm-display"
        # and a few attributes that are not setup by inject_data.py
        assert data["internationalizationEnabled"] == False
        assert data["clientAuthenticationFlow"] == "clients"

        data = json.load(open(os.path.join(datadir, "master/master.json")))
        assert list(data.keys()) == [
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
            'clientOfflineSessionIdleTimeout',
            'clientOfflineSessionMaxLifespan',
            'clientPolicies',
            'clientProfiles',
            'clientSessionIdleTimeout',
            'clientSessionMaxLifespan',
            'defaultRole',
            'defaultSignatureAlgorithm',
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
            'identityProviders',
            'internationalizationEnabled',
            'loginWithEmailAllowed',
            'maxDeltaTimeSeconds',
            'maxFailureWaitSeconds',
            'minimumQuickLoginWaitSeconds',
            'notBefore',
            'oauth2DeviceCodeLifespan',
            'oauth2DevicePollingInterval',
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

import glob

from pytest import mark
import json
import os
import shutil

from pytest_unordered import unordered

from kcfetcher.fetch import CustomAuthenticationFetch
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login, RH_SSO_VERSIONS_7_4, RH_SSO_VERSIONS_7_5


def kc_15_auth_flow_expected_data_fixup(kc, data):
    """
    For authentication flow,
    KC 9/RH SSO 7.4 will return
        "autheticatorFlow": False,
    KC 15/RH SSO 7.5 will return
        "authenticatorFlow": False,
        "autheticatorFlow": False,
    """
    assert isinstance(data, dict)
    if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_5:
        for exec in data["authenticationExecutions"]:
            assert "autheticatorFlow" in exec
            assert "authenticatorFlow" not in exec
            exec["authenticatorFlow"] = exec["autheticatorFlow"]

    if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_5:
        authenticator_field_name = "authenticator___kc15"
    else:
        authenticator_field_name = "authenticator___kc9"
    for exec in data["authenticationExecutions"]:
        if authenticator_field_name in exec:
            exec["authenticator"] = exec[authenticator_field_name]
        for field_name in ["authenticator___kc9", "authenticator___kc15"]:
            if field_name in exec:
                exec.pop(field_name)
    return data


def kc_15_auth_flow_executors_expected_data_fixup(kc, data):
    # KC 15/RH SSO 7.5 added (optional) description field
    # KC 9 has description field , but (default value) is differen.
    # Choose correct description from two options.
    assert isinstance(data, list)
    assert isinstance(data[0], dict)
    if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_4:
        desc_field_name = "description___kc9"
    else:
        desc_field_name = "description___kc15"
    for exec in data:
        if desc_field_name in exec:
            exec["description"] = exec[desc_field_name]
        for field_name in ["description___kc9", "description___kc15"]:
            if field_name in exec:
                exec.pop(field_name)
    return data


class TestCustomAuthenticationFetch:
    @mark.vcr()
    def test_fetch_master(self):
        datadir = "output/ci/outd"
        remove_folder(datadir)
        make_folder(datadir)
        store_api = Store(datadir)
        server = os.environ["SSO_API_URL"]
        user = os.environ["SSO_API_USERNAME"]
        password = os.environ["SSO_API_PASSWORD"]
        kc = login(server, user, password)
        realm_name = "master"
        resource_name = "authentication"
        resource_identifier = "alias"

        obj = CustomAuthenticationFetch(kc, resource_name, resource_identifier, realm_name)

        obj.fetch(store_api)

        # check generated content
        assert unordered(glob.glob('**', root_dir=datadir, recursive=True)) == [
            'flows',
            'flows/registration',
            'flows/registration/executors',
            'flows/registration/executors/executors.json',
            'flows/registration/registration.json',
            'flows/browser',
            'flows/browser/executors',
            'flows/browser/executors/executors.json',
            'flows/browser/browser.json',
            'flows/reset_credentials',
            'flows/reset_credentials/executors',
            'flows/reset_credentials/executors/executors.json',
            'flows/reset_credentials/reset_credentials.json',
            'flows/http_challenge',
            'flows/http_challenge/executors',
            'flows/http_challenge/executors/executors.json',
            'flows/http_challenge/http_challenge.json',
            'flows/direct_grant',
            'flows/direct_grant/executors',
            'flows/direct_grant/executors/executors.json',
            'flows/direct_grant/direct_grant.json',
            'flows/clients',
            'flows/clients/executors',
            'flows/clients/executors/executors.json',
            'flows/clients/clients.json',
            'flows/docker_auth',
            'flows/docker_auth/executors',
            'flows/docker_auth/executors/executors.json',
            'flows/docker_auth/docker_auth.json',
            'flows/first_broker_login',
            'flows/first_broker_login/executors',
            'flows/first_broker_login/executors/executors.json',
            'flows/first_broker_login/first_broker_login.json',
        ]

        data = json.load(open(os.path.join(datadir, "flows/browser/browser.json")))
        assert data == kc_15_auth_flow_expected_data_fixup(kc, {
            "alias": "browser",
            "authenticationExecutions": [
                {
                    "authenticator": "auth-cookie",
                    "autheticatorFlow": False,
                    "priority": 10,
                    "requirement": "ALTERNATIVE",
                    "userSetupAllowed": False
                },
                {
                    "authenticator": "auth-spnego",
                    "autheticatorFlow": False,
                    "priority": 20,
                    "requirement": "DISABLED",
                    "userSetupAllowed": False
                },
                {
                    "authenticator": "identity-provider-redirector",
                    "autheticatorFlow": False,
                    "priority": 25,
                    "requirement": "ALTERNATIVE",
                    "userSetupAllowed": False
                },
                {
                    "autheticatorFlow": True,
                    "flowAlias": "forms",
                    "priority": 30,
                    "requirement": "ALTERNATIVE",
                    "userSetupAllowed": False
                }
            ],
            "builtIn": True,
            "description": "browser based authentication",
            "providerId": "basic-flow",
            "topLevel": True
        })

        data = json.load(open(os.path.join(datadir, "flows/browser/executors/executors.json")))
        assert data == kc_15_auth_flow_executors_expected_data_fixup(kc, [
            {
                "configurable": False,
                "displayName": "Cookie",
                "index": 0,
                "level": 0,
                "providerId": "auth-cookie",
                "requirement": "ALTERNATIVE",
                "requirementChoices": [
                    "REQUIRED",
                    "ALTERNATIVE",
                    "DISABLED"
                ]
            },
            {
                "configurable": False,
                "displayName": "Kerberos",
                "index": 1,
                "level": 0,
                "providerId": "auth-spnego",
                "requirement": "DISABLED",
                "requirementChoices": [
                    "REQUIRED",
                    "ALTERNATIVE",
                    "DISABLED"
                ]
            },
            {
                "configurable": True,
                "displayName": "Identity Provider Redirector",
                "index": 2,
                "level": 0,
                "providerId": "identity-provider-redirector",
                "requirement": "ALTERNATIVE",
                "requirementChoices": [
                    "REQUIRED",
                    "ALTERNATIVE",
                    "DISABLED"
                ]
            },
            {
                "authenticationFlow": True,
                "configurable": False,
                # "description___kc9": "Username, password, otp and other auth forms.",
                "description___kc15": "Username, password, otp and other auth forms.",
                "displayName": "forms",
                "index": 3,
                "level": 0,
                "requirement": "ALTERNATIVE",
                "requirementChoices": [
                    "REQUIRED",
                    "ALTERNATIVE",
                    "DISABLED",
                    "CONDITIONAL"
                ]
            },
            {
                "configurable": False,
                "displayName": "Username Password Form",
                "index": 0,
                "level": 1,
                "providerId": "auth-username-password-form",
                "requirement": "REQUIRED",
                "requirementChoices": [
                    "REQUIRED"
                ]
            },
            {
                "authenticationFlow": True,
                "configurable": False,
                #"description___kc9s": "Flow to determine if the OTP is required for the authentication",
                "description___kc15": "Flow to determine if the OTP is required for the authentication",
                "displayName": "Browser - Conditional OTP",
                "index": 1,
                "level": 1,
                "requirement": "CONDITIONAL",
                "requirementChoices": [
                    "REQUIRED",
                    "ALTERNATIVE",
                    "DISABLED",
                    "CONDITIONAL"
                ]
            },
            {
                "configurable": False,
                "displayName": "Condition - user configured",
                "index": 0,
                "level": 2,
                "providerId": "conditional-user-configured",
                "requirement": "REQUIRED",
                "requirementChoices": [
                    "REQUIRED",
                    "DISABLED"
                ]
            },
            {
                "configurable": False,
                "displayName": "OTP Form",
                "index": 1,
                "level": 2,
                "providerId": "auth-otp-form",
                "requirement": "REQUIRED",
                "requirementChoices": [
                    "REQUIRED",
                    "ALTERNATIVE",
                    "DISABLED"
                ]
            }
        ])

    @mark.vcr()
    def test_fetch_ci0_realm(self):
        datadir = "output/ci/outd"
        remove_folder(datadir)
        make_folder(datadir)
        store_api = Store(datadir)
        server = os.environ["SSO_API_URL"]
        user = os.environ["SSO_API_USERNAME"]
        password = os.environ["SSO_API_PASSWORD"]
        kc = login(server, user, password)
        realm_name = "ci0-realm"
        resource_name = "authentication"
        resource_identifier = "alias"

        obj = CustomAuthenticationFetch(kc, resource_name, resource_identifier, realm_name)

        obj.fetch(store_api)

        # check generated content
        assert unordered(glob.glob('**', root_dir=datadir, recursive=True)) == [
            'flows',
            'flows/registration',
            'flows/registration/executors',
            'flows/registration/executors/executors.json',
            'flows/registration/registration.json',
            'flows/browser',
            'flows/browser/executors',
            'flows/browser/executors/executors.json',
            'flows/browser/browser.json',
            'flows/reset_credentials',
            'flows/reset_credentials/executors',
            'flows/reset_credentials/executors/executors.json',
            'flows/reset_credentials/reset_credentials.json',
            'flows/http_challenge',
            'flows/http_challenge/executors',
            'flows/http_challenge/executors/executors.json',
            'flows/http_challenge/http_challenge.json',
            'flows/direct_grant',
            'flows/direct_grant/executors',
            'flows/direct_grant/executors/executors.json',
            'flows/direct_grant/direct_grant.json',
            'flows/clients',
            'flows/clients/executors',
            'flows/clients/executors/executors.json',
            'flows/clients/clients.json',
            'flows/docker_auth',
            'flows/docker_auth/executors',
            'flows/docker_auth/executors/executors.json',
            'flows/docker_auth/docker_auth.json',
            'flows/first_broker_login',
            'flows/first_broker_login/executors',
            'flows/first_broker_login/executors/executors.json',
            'flows/first_broker_login/first_broker_login.json',
            # what inject_data.py added
            'flows/ci0-auth-flow-generic',
            'flows/ci0-auth-flow-generic/executors',
            'flows/ci0-auth-flow-generic/executors/executors.json',
            'flows/ci0-auth-flow-generic/ci0-auth-flow-generic.json',
        ]

        # -------------------------------------------------------------------------------
        # Check browser flow. It is unmodified.
        data = json.load(open(os.path.join(datadir, "flows/browser/browser.json")))
        assert data == kc_15_auth_flow_expected_data_fixup(kc, {
            "alias": "browser",
            "authenticationExecutions": [
                {
                    "authenticator": "auth-cookie",
                    "autheticatorFlow": False,
                    "priority": 10,
                    "requirement": "ALTERNATIVE",
                    "userSetupAllowed": False
                },
                {
                    "authenticator": "auth-spnego",
                    "autheticatorFlow": False,
                    "priority": 20,
                    "requirement": "ALTERNATIVE",
                    "userSetupAllowed": False
                },
                {
                    "authenticator": "identity-provider-redirector",
                    "autheticatorFlow": False,
                    "priority": 25,
                    "requirement": "ALTERNATIVE",
                    "userSetupAllowed": False
                },
                {
                    "autheticatorFlow": True,
                    "flowAlias": "forms",
                    "priority": 30,
                    "requirement": "ALTERNATIVE",
                    "userSetupAllowed": False
                }
            ],
            "builtIn": True,
            "description": "browser based authentication",
            "providerId": "basic-flow",
            "topLevel": True
        })

        data = json.load(open(os.path.join(datadir, "flows/browser/executors/executors.json")))
        assert data == kc_15_auth_flow_executors_expected_data_fixup(kc, [
            {
                "configurable": False,
                "displayName": "Cookie",
                "index": 0,
                "level": 0,
                "providerId": "auth-cookie",
                "requirement": "ALTERNATIVE",
                "requirementChoices": [
                    "REQUIRED",
                    "ALTERNATIVE",
                    "DISABLED"
                ]
            },
            {
                "configurable": False,
                "displayName": "Kerberos",
                "index": 1,
                "level": 0,
                "providerId": "auth-spnego",
                "requirement": "ALTERNATIVE",
                "requirementChoices": [
                    "REQUIRED",
                    "ALTERNATIVE",
                    "DISABLED"
                ]
            },
            {
                "configurable": True,
                "displayName": "Identity Provider Redirector",
                "index": 2,
                "level": 0,
                "providerId": "identity-provider-redirector",
                "requirement": "ALTERNATIVE",
                "requirementChoices": [
                    "REQUIRED",
                    "ALTERNATIVE",
                    "DISABLED"
                ]
            },
            {
                "authenticationFlow": True,
                "configurable": False,
                "description___kc15": "Username, password, otp and other auth forms.",
                "displayName": "forms",
                "index": 3,
                "level": 0,
                "requirement": "ALTERNATIVE",
                "requirementChoices": [
                    "REQUIRED",
                    "ALTERNATIVE",
                    "DISABLED",
                    "CONDITIONAL"
                ]
            },
            {
                "configurable": False,
                "displayName": "Username Password Form",
                "index": 0,
                "level": 1,
                "providerId": "auth-username-password-form",
                "requirement": "REQUIRED",
                "requirementChoices": [
                    "REQUIRED"
                ]
            },
            {
                "authenticationFlow": True,
                "configurable": False,
                # "description___kc9": "Flow to determine if the OTP is required for the authentication",
                "description___kc15": "Flow to determine if the OTP is required for the authentication",
                "displayName": "Browser - Conditional OTP",
                "index": 1,
                "level": 1,
                "requirement": "CONDITIONAL",
                "requirementChoices": [
                    "REQUIRED",
                    "ALTERNATIVE",
                    "DISABLED",
                    "CONDITIONAL"
                ]
            },
            {
                "configurable": False,
                "displayName": "Condition - user configured",
                "index": 0,
                "level": 2,
                "providerId": "conditional-user-configured",
                "requirement": "REQUIRED",
                "requirementChoices": [
                    "REQUIRED",
                    "DISABLED"
                ]
            },
            {
                "configurable": False,
                "displayName": "OTP Form",
                "index": 1,
                "level": 2,
                "providerId": "auth-otp-form",
                "requirement": "REQUIRED",
                "requirementChoices": [
                    "REQUIRED",
                    "ALTERNATIVE",
                    "DISABLED"
                ]
            }
        ])

        # -------------------------------------------------------------------------------
        # Check ci0-auth-flow-generic flow. It is non-default, executions are configured etc.
        data = json.load(open(os.path.join(datadir, "flows/ci0-auth-flow-generic/ci0-auth-flow-generic.json")))
        assert data == kc_15_auth_flow_expected_data_fixup(kc, {
            "alias": "ci0-auth-flow-generic",
            "authenticationExecutions": [
                {
                    "authenticator": "direct-grant-validate-username",
                    "autheticatorFlow": False,
                    "priority": 0,
                    "requirement": "REQUIRED",
                    "userSetupAllowed": False
                },
                {
                    "authenticator": "auth-conditional-otp-form",
                    "authenticatorConfig": "ci0-auth-flow-generic-exec-20-alias",
                    "autheticatorFlow": False,
                    "priority": 1,
                    "requirement": "ALTERNATIVE",
                    "userSetupAllowed": False
                },
                {
                    "authenticator___kc9": "registration-page-form",  # only in KC9
                    "autheticatorFlow": True,
                    "flowAlias": "ci0-auth-flow-generic-exec-3-generic-alias",
                    "priority": 2,
                    "requirement": "CONDITIONAL",
                    "userSetupAllowed": False
                },
                {
                    "authenticator": "registration-page-form",
                    "autheticatorFlow": True,
                    "flowAlias": "ci0-auth-flow-generic-exec-4-flow-alias",
                    "priority": 3,
                    "requirement": "REQUIRED",
                    "userSetupAllowed": False
                }
            ],
            "builtIn": False,
            "description": "ci0-auth-flow-generic-desc",
            "providerId": "basic-flow",
            "topLevel": True
        })

        data = json.load(open(os.path.join(datadir, "flows/ci0-auth-flow-generic/executors/executors.json")))
        assert data == kc_15_auth_flow_executors_expected_data_fixup(kc, [
            {
                "configurable": False,
                "displayName": "Username Validation",
                "index": 0,
                "level": 0,
                "providerId": "direct-grant-validate-username",
                "requirement": "REQUIRED",
                "requirementChoices": [
                    "REQUIRED"
                ]
            },
            {
                "alias": "ci0-auth-flow-generic-exec-20-alias",
                "authenticationConfigData": {
                    "alias": "ci0-auth-flow-generic-exec-20-alias",
                    "config": {
                        "defaultOtpOutcome": "skip",
                        "forceOtpForHeaderPattern": "ci0-force-header",
                        "forceOtpRole": "ci0-client-0.ci0-client0-role0",
                        "noOtpRequiredForHeaderPattern": "ci0-skip-header",
                        "otpControlAttribute": "user-attr",
                        "skipOtpRole": "ci0-role-1"
                    }
                },
                "configurable": True,
                # "description": "Username, password, otp and other auth forms.",
                "displayName": "Conditional OTP Form",
                "index": 1,
                "level": 0,
                "providerId": "auth-conditional-otp-form",
                "requirement": "ALTERNATIVE",
                "requirementChoices": [
                    "REQUIRED",
                    "ALTERNATIVE",
                    "DISABLED"
                ]
            },
            {
                "authenticationFlow": True,
                "configurable": False,
                "description___kc15": "ci0-auth-flow-generic-exec-3-generic-alias-desc",
                "displayName": "ci0-auth-flow-generic-exec-3-generic-alias",
                "index": 2,
                "level": 0,
                "requirement": "CONDITIONAL",
                "requirementChoices": [
                    "REQUIRED",
                    "ALTERNATIVE",
                    "DISABLED",
                    "CONDITIONAL"
                ]
            },
            {
                "authenticationFlow": True,
                "configurable": False,
                "description___kc15": "ci0-auth-flow-generic-exec-3-1-flow-alias-desc",
                "displayName": "ci0-auth-flow-generic-exec-3-1-flow-alias",
                "index": 0,
                "level": 1,
                "requirement": "ALTERNATIVE",
                "requirementChoices": [
                    "REQUIRED",
                    "ALTERNATIVE",
                    "DISABLED",
                    "CONDITIONAL"
                ]
            },
            {
                "authenticationFlow": True,
                "configurable": False,
                #"description___kc9": "Username, password, otp and other auth forms.",
                "description___kc15": "ci0-auth-flow-generic-exec-4-flow-alias-desc",
                "displayName": "ci0-auth-flow-generic-exec-4-flow-alias",
                "index": 3,
                "level": 0,
                "providerId": "registration-page-form",
                "requirement": "REQUIRED",
                "requirementChoices": [
                    "REQUIRED",
                    "DISABLED"
                ]
            },
            {
                "alias": "ci0-auth-flow-generic-exec-6-alias",
                "authenticationConfigData": {
                    "alias": "ci0-auth-flow-generic-exec-6-alias",
                    "config": {
                        "secret": "ci0-recaptcha-secret",
                        "site.key": "ci0-recaptcha-site-key",
                        "useRecaptchaNet": "true"
                    }
                },
                "configurable": True,
                "displayName": "Recaptcha",
                "index": 0,
                "level": 1,
                "providerId": "registration-recaptcha-action",
                "requirement": "DISABLED",
                "requirementChoices": [
                    "REQUIRED",
                    "DISABLED"
                ]
            }
        ])

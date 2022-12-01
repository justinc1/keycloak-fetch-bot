import glob

from pytest import mark
import json
import os
import shutil

from pytest_unordered import unordered

from kcfetcher.fetch import CustomAuthenticationFetch
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login


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
            'registration',
            'registration/executors',
            'registration/executors/executors.json',
            'registration/registration.json',
            'browser',
            'browser/executors',
            'browser/executors/executors.json',
            'browser/browser.json',
            'reset_credentials',
            'reset_credentials/executors',
            'reset_credentials/executors/executors.json',
            'reset_credentials/reset_credentials.json',
            'http_challenge',
            'http_challenge/executors',
            'http_challenge/executors/executors.json',
            'http_challenge/http_challenge.json',
            'direct_grant',
            'direct_grant/executors',
            'direct_grant/executors/executors.json',
            'direct_grant/direct_grant.json',
            'clients',
            'clients/executors',
            'clients/executors/executors.json',
            'clients/clients.json',
            'docker_auth',
            'docker_auth/executors',
            'docker_auth/executors/executors.json',
            'docker_auth/docker_auth.json',
            'first_broker_login',
            'first_broker_login/executors',
            'first_broker_login/executors/executors.json',
            'first_broker_login/first_broker_login.json',
        ]

        data = json.load(open(os.path.join(datadir, "browser/browser.json")))
        assert data == {
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
        }

        data = json.load(open(os.path.join(datadir, "browser/executors/executors.json")))
        assert data == [
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
        ]

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
            'registration',
            'registration/executors',
            'registration/executors/executors.json',
            'registration/registration.json',
            'browser',
            'browser/executors',
            'browser/executors/executors.json',
            'browser/browser.json',
            'reset_credentials',
            'reset_credentials/executors',
            'reset_credentials/executors/executors.json',
            'reset_credentials/reset_credentials.json',
            'http_challenge',
            'http_challenge/executors',
            'http_challenge/executors/executors.json',
            'http_challenge/http_challenge.json',
            'direct_grant',
            'direct_grant/executors',
            'direct_grant/executors/executors.json',
            'direct_grant/direct_grant.json',
            'clients',
            'clients/executors',
            'clients/executors/executors.json',
            'clients/clients.json',
            'docker_auth',
            'docker_auth/executors',
            'docker_auth/executors/executors.json',
            'docker_auth/docker_auth.json',
            'first_broker_login',
            'first_broker_login/executors',
            'first_broker_login/executors/executors.json',
            'first_broker_login/first_broker_login.json',
            # what inject_data.py added
            'ci0-auth-flow-generic',
            'ci0-auth-flow-generic/executors',
            'ci0-auth-flow-generic/executors/executors.json',
            'ci0-auth-flow-generic/ci0-auth-flow-generic.json',
            'ci0-auth-flow-generic/execution-config/',
            'ci0-auth-flow-generic/execution-config/ci0-auth-flow-generic-exec-20-alias.json',
            'ci0-auth-flow-generic/execution-config/ci0-auth-flow-generic-exec-6-alias.json',
        ]

        # -------------------------------------------------------------------------------
        # Check browser flow. It is unmodified.
        data = json.load(open(os.path.join(datadir, "browser/browser.json")))
        assert data == {
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
        }

        data = json.load(open(os.path.join(datadir, "browser/executors/executors.json")))
        assert data == [
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
        ]

        # -------------------------------------------------------------------------------
        # Check ci0-auth-flow-generic flow. It is non-default, executions are configured etc.
        data = json.load(open(os.path.join(datadir, "ci0-auth-flow-generic/ci0-auth-flow-generic.json")))
        assert data == {
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
                    "authenticator": "registration-page-form",
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
        }

        data = json.load(open(os.path.join(datadir, "ci0-auth-flow-generic/executors/executors.json")))
        assert data == [
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
                "authenticationConfig": "19c5be2a-d37d-4fd6-9872-0a875fda8007",  # TODO UUID to name
                "configurable": True,
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
                "authenticationConfig": "39719cee-eee5-4791-8b21-afb0763ab609",  # TODO UUID to name
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
        ]

        data = json.load(open(os.path.join(datadir, "ci0-auth-flow-generic/execution-config/ci0-auth-flow-generic-exec-20-alias.json")))
        assert data == {
            "alias": "ci0-auth-flow-generic-exec-20-alias",
            "config": {
                "skipOtpRole": "ci0-role-1",
                "forceOtpRole": "ci0-client-0.ci0-client0-role0",
                "otpControlAttribute": "user-attr",
                "noOtpRequiredForHeaderPattern": "ci0-skip-header",
                "forceOtpForHeaderPattern": "ci0-force-header",
                "defaultOtpOutcome": "skip"
            }
        }

        data = json.load(open(os.path.join(datadir, "ci0-auth-flow-generic/execution-config/ci0-auth-flow-generic-exec-6-alias.json")))
        assert data == {
            "alias": "ci0-auth-flow-generic-exec-6-alias",
            "config": {
                "useRecaptchaNet": "true",
                "secret": "ci0-recaptcha-secret",
                "site.key": "ci0-recaptcha-site-key"
            }
        }

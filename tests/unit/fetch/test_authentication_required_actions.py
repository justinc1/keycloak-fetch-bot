import glob

from pytest import mark
import json
import os
import shutil

from pytest_unordered import unordered

from kcfetcher.fetch import GenericFetch
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login, RH_SSO_VERSIONS_7_4, RH_SSO_VERSIONS_7_5


def get_default_required_actions(kc):
    req_actions = [
        'configure_totp.json',
        'terms_and_conditions.json',
        'update_password.json',
        'update_profile.json',
        'update_user_locale.json',
        'verify_email.json',
    ]
    if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_5:
        req_actions += ["delete_account.json"]
    return req_actions


class TestAuthenticationRequiredActionsFetch:
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
        resource_name = "authentication/required-actions"
        resource_identifier = "alias"

        obj = GenericFetch(kc, resource_name, resource_identifier, realm_name)

        obj.fetch(store_api)

        # check generated content
        expected_required_actions = get_default_required_actions(kc)
        assert unordered(glob.glob('**', root_dir=datadir, recursive=True)) == expected_required_actions

        data = json.load(open(os.path.join(datadir, "configure_totp.json")))
        assert data == {
            "alias": "CONFIGURE_TOTP",
            "config": {},
            "defaultAction": False,
            "enabled": True,
            "name": "Configure OTP",
            "priority": 10,
            "providerId": "CONFIGURE_TOTP",
        }

        data = json.load(open(os.path.join(datadir, "terms_and_conditions.json")))
        assert data == {
            "alias": "terms_and_conditions",
            "config": {},
            "defaultAction": False,
            "enabled": False,
            "name": "Terms and Conditions",
            "priority": 20,
            "providerId": "terms_and_conditions"
        }

        data = json.load(open(os.path.join(datadir, "update_user_locale.json")))
        assert data == {
            "alias": "update_user_locale",
            "config": {},
            "defaultAction": False,
            "enabled": True,
            "name": "Update User Locale",
            "priority": 1000,
            "providerId": "update_user_locale",
        }

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
        resource_name = "authentication/required-actions"
        resource_identifier = "alias"

        obj = GenericFetch(kc, resource_name, resource_identifier, realm_name)

        obj.fetch(store_api)

        # check generated content
        expected_required_actions = get_default_required_actions(kc)
        if 0:
            # This is possible in KC 9.0, but not in RH SSO 7.4. Skip the test.
            expected_required_actions += ['webauthn-register.json']
        assert unordered(glob.glob('**', root_dir=datadir, recursive=True)) == expected_required_actions

        data = json.load(open(os.path.join(datadir, "configure_totp.json")))
        assert data == {
            "alias": "CONFIGURE_TOTP",
            "config": {},
            "defaultAction": True,  # changed from default
            "enabled": True,
            "name": "Configure OTP",
            "priority": 10,
            "providerId": "CONFIGURE_TOTP",
        }

        data = json.load(open(os.path.join(datadir, "terms_and_conditions.json")))
        assert data == {
            "alias": "terms_and_conditions",
            "config": {},
            "defaultAction": False,
            "enabled": True,
            "name": "Terms and Conditions",
            "priority": 20,
            "providerId": "terms_and_conditions"
        }

        data = json.load(open(os.path.join(datadir, "update_user_locale.json")))
        assert data == {
            "alias": "update_user_locale",
            "config": {},
            "defaultAction": False,
            "enabled": True,
            "name": "Update User Locale",
            "priority": 1000,  # changed from default as side effect of raising webauthn-register priority
            "providerId": "update_user_locale",
        }

        if 0:
            # This is possible in KC 9.0, but not in RH SSO 7.4. Skip the test.
            data = json.load(open(os.path.join(datadir, "webauthn-register.json")))
            assert data == {
                "alias": "webauthn-register",
                "config": {},
                "defaultAction": False,
                "enabled": True,
                "name": "Webauthn Register",
                "priority": 1000,
                "providerId": "webauthn-register",
            }

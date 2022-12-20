import glob
from operator import itemgetter

from pytest import mark
from pytest_unordered import unordered
import json
import os
import shutil
from kcfetcher.fetch import IdentityProviderFetch
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login


@mark.vcr()
class TestIdentityProviderFetch:
    def test_fetch(self):
        datadir = "output/ci/outd"
        remove_folder(datadir)
        make_folder(datadir)
        store_api = Store(datadir)
        server = os.environ["SSO_API_URL"]
        user = os.environ["SSO_API_USERNAME"]
        password = os.environ["SSO_API_PASSWORD"]
        kc = login(server, user, password)

        realm_name = "ci0-realm"
        resource_name = "identity-provider"
        resource_identifier = "alias"
        obj = IdentityProviderFetch(kc, resource_name, resource_identifier, realm_name)

        obj.fetch(store_api)

        # check generated content
        assert unordered(glob.glob('**', root_dir=datadir, recursive=True)) == [
            'ci0-idp-saml-0.json',
        ]

        data = json.load(open(os.path.join(datadir, "ci0-idp-saml-0.json")))
        assert data == {
            "addReadTokenRoleOnCreate": False,
            "alias": "ci0-idp-saml-0",
            "authenticateByDefault": False,
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
            "displayName": "ci0-idp-saml-0-displayName",
            "enabled": True,
            "firstBrokerLoginFlowAlias": "first broker login",
            "linkOnly": False,
            "providerId": "saml",
            "storeToken": False,
            "trustEmail": False,
            "updateProfileFirstLoginMode": "on"
        }

        # IdP mappers - they are stored in the realm.json

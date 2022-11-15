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
        assert os.listdir(datadir) == unordered(["ci0-idp-saml-0.json"])
        #
        data = json.load(open(os.path.join(datadir, "ci0-idp-saml-0.json")))
        assert list(data.keys()) == [
            'addReadTokenRoleOnCreate',
            'alias',
            'authenticateByDefault',
            'config',
            'displayName',
            'enabled',
            'firstBrokerLoginFlowAlias',
            # 'internalId',
            'linkOnly',
            'providerId',
            'storeToken',
            'trustEmail',
            'updateProfileFirstLoginMode',
        ]
        assert list(data["config"].keys()) == [
            'allowCreate',
            'authnContextClassRefs',
            'authnContextComparisonType',
            'authnContextDeclRefs',
            'entityId',
            'nameIDPolicyFormat',
            'principalType',
            'signatureAlgorithm',
            'singleLogoutServiceUrl',
            'singleSignOnServiceUrl',
            'syncMode',
            'useJwksUrl',
            'wantAssertionsEncrypted',
            'xmlSigKeyInfoKeyNameTransformer',
        ]
        assert data["alias"] == "ci0-idp-saml-0"
        assert data["config"]["entityId"] == "https://172.17.0.2:8443/auth/realms/ci0-realm"

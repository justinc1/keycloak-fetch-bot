from pytest import mark
from pytest_unordered import unordered
import json
import os
import shutil
from kcfetcher.fetch import ClientScopeFetch
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login


@mark.vcr()
class TestClientScopeFetch:
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
        resource_name = "client-scopes"
        resource_identifier = "name"
        obj = ClientScopeFetch(kc, resource_name, resource_identifier, realm_name)

        obj.fetch(store_api)

        # check generated content
        assert os.listdir(datadir) == ["ci0-client-scope.json"]
        #
        data = json.load(open(os.path.join(datadir, "ci0-client-scope.json")))
        assert list(data.keys()) == [
            'attributes',
            'description',
            'name',
            'protocol',
            'protocolMappers',
        ]
        assert data["name"] == "ci0-client-scope"

        # check protocol mappers
        assert len(data["protocolMappers"]) == 1
        assert list(data["protocolMappers"][0].keys()) == [
            'config',
            'consentRequired',
            'name',
            'protocol',
            'protocolMapper',
        ]
        assert data["protocolMappers"][0]["protocolMapper"] == "oidc-usermodel-attribute-mapper"
        assert list(data["protocolMappers"][0]["config"].keys()) == [
            'access.token.claim',
            'claim.name',
            'id.token.claim',
            'jsonType.label',
            'user.attribute',
            'userinfo.token.claim',
        ]
        assert data["protocolMappers"][0]["config"]["user.attribute"] == "birthdate"
        assert data["protocolMappers"][0]["config"]["claim.name"] == "birthdate"

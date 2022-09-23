from pytest import mark
import json
import os
import shutil
from kcfetcher.fetch import ClientFetch
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login


class MockupStoreApi:
    def add_child(self, child_name):
        pass

    def store_one(self, data, identifier):
        pass

    def store_one_with_alias(self, alias, data):
        pass

    def remove_last_child(self):
        pass


class MockupKc:
    def build(self, name, realm):
        return MockupClients()


class MockupClients:
    def roles(self, query):
        return {}

    def all(self):
        return []


# manually written mockup classes
class TestClientFetch:
    def test_fetch(self):
        store_api = MockupStoreApi()
        kc = MockupKc()
        resource_name = "clients"

        obj = ClientFetch(kc, resource_name)
        obj.id = "clientId"
        obj.realm = "ci-realm"

        obj.fetch(store_api)


@mark.vcr()
class TestClientFetch_vcr:
    def test_fetch(self):
        datadir = "output/ci/outd"
        remove_folder(datadir)
        make_folder(datadir)
        store_api = Store(datadir)
        server = os.environ["SSO_API_URL"]
        user = os.environ["SSO_API_USERNAME"]
        password = os.environ["SSO_API_PASSWORD"]
        kc = login(server, user, password)
        realm_name = "master"
        resource_name = "clients"
        resource_identifier = "clientId"

        obj = ClientFetch(kc, resource_name, resource_identifier, realm_name)

        obj.fetch(store_api)

        # check generated content
        assert os.listdir(datadir) == ["client-0"]
        assert os.listdir(os.path.join(datadir, "client-0")) == ['master-realm.json', 'roles']
        assert os.listdir(os.path.join(datadir, "client-0/roles")) == ['roles.json']
        #
        data = json.load(open(os.path.join(datadir, "client-0/master-realm.json")))
        assert list(data.keys()) == [
            'access',
            'alwaysDisplayInConsole',
            'attributes',
            'authenticationFlowBindingOverrides',
            'bearerOnly',
            'clientAuthenticatorType',
            'clientId',
            'consentRequired',
            'defaultClientScopes',
            'directAccessGrantsEnabled',
            'enabled',
            'frontchannelLogout',
            'fullScopeAllowed',
            'implicitFlowEnabled',
            'name',
            'nodeReRegistrationTimeout',
            'notBefore',
            'optionalClientScopes',
            'publicClient',
            'redirectUris',
            'serviceAccountsEnabled',
            'standardFlowEnabled',
            'surrogateAuthRequired',
            'webOrigins',
        ]
        assert data["clientId"] == "master-realm"
        assert data["name"] == "master Realm"
        assert os.listdir(os.path.join(datadir, "client-0/roles")) == ['roles.json']
        #
        data = json.load(open(os.path.join(datadir, "client-0/roles/roles.json")))
        assert isinstance(data, list)
        assert len(data) == 18
        role = data[0]
        assert list(role.keys()) == [
            'clientRole',
            'composite',
            'containerId',
            'description',
            'name',
        ]
        assert role["name"] == "view-authorization"
        assert role["description"] == "${role_view-authorization}"

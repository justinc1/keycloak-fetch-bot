from pytest import mark
from pytest_unordered import unordered
import json
import os
from kcfetcher.fetch import ClientFetch
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login


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
        realm_name = "ci0-realm"
        resource_name = "clients"
        resource_identifier = "clientId"

        obj = ClientFetch(kc, resource_name, resource_identifier, realm_name)

        obj.fetch(store_api)

        # check generated content
        assert os.listdir(datadir) == unordered(["client-0", "client-1"])
        assert os.listdir(os.path.join(datadir, "client-0")) == unordered(['ci0-client-0.json', 'roles'])
        assert os.listdir(os.path.join(datadir, "client-0/roles")) == ['roles.json']
        assert os.listdir(os.path.join(datadir, "client-1")) == unordered(['ci0-client-1.json', 'roles'])
        assert os.listdir(os.path.join(datadir, "client-1/roles")) == ['roles.json']
        #
        data = json.load(open(os.path.join(datadir, "client-0/ci0-client-0.json")))
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
            'description',
            'directAccessGrantsEnabled',
            'enabled',
            'frontchannelLogout',
            'fullScopeAllowed',
            'implicitFlowEnabled',
            'name',
            'nodeReRegistrationTimeout',
            'notBefore',
            'optionalClientScopes',
            'protocol',
            'publicClient',
            'redirectUris',
            'serviceAccountsEnabled',
            'standardFlowEnabled',
            'surrogateAuthRequired',
            'webOrigins',
        ]
        assert data["clientId"] == "ci0-client-0"
        assert data["name"] == "ci0-client-0-name"
        assert os.listdir(os.path.join(datadir, "client-0/roles")) == ['roles.json']
        #
        data = json.load(open(os.path.join(datadir, "client-0/roles/roles.json")))
        assert isinstance(data, list)
        assert len(data) == 1
        role = data[0]
        assert list(role.keys()) == [
            'clientRole',
            'composite',
            'containerId',
            'description',
            'name',
        ]
        assert role["name"] == "ci0-client0-role0"
        assert role["description"] == "ci0-client0-role0-desc"

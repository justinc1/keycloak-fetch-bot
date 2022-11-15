from pytest import mark
from pytest_unordered import unordered
import json
import os
import shutil
from kcfetcher.fetch import GenericFetch
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login


@mark.vcr()
class TestRoleFetch_vcr:
    def test__get_data(self):
        datadir = "output/ci/outd"
        remove_folder(datadir)
        make_folder(datadir)
        store_api = Store(datadir)
        server = os.environ["SSO_API_URL"]
        user = os.environ["SSO_API_USERNAME"]
        password = os.environ["SSO_API_PASSWORD"]
        kc = login(server, user, password)
        realm_name = "ci0-realm"
        resource_name = "roles"
        resource_identifier = "name"

        obj = GenericFetch(kc, resource_name, resource_identifier, realm_name)

        obj.fetch(store_api)

        # check generated content
        assert unordered(os.listdir(datadir)) == [
            'ci0-role-0.json',
            'ci0-role-1a.json',
            'ci0-role-1b.json',
            'default-roles-ci0-realm.json',
        ]
        #
        data = json.load(open(os.path.join(datadir, "ci0-role-0.json")))
        assert list(data.keys()) == [
            'clientRole',
            'composite',
            'containerId', # TODO remove
            'description',
            'name',
        ]
        assert data["name"] == "ci0-role-0"
        assert data["clientRole"] is False
        assert data["composite"] is False


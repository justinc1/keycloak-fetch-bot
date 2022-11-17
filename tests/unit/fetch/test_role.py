from pytest import mark
from pytest_unordered import unordered
import json
import os
import shutil
from kcfetcher.fetch import RoleFetch
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login, RH_SSO_VERSIONS_7_5


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

        obj = RoleFetch(kc, resource_name, resource_identifier, realm_name)

        obj.fetch(store_api)

        # check generated content
        expected_files = [
            'ci0-role-0.json',
            'ci0-role-1.json',
            'ci0-role-1a.json',
            'ci0-role-1b.json',
            # 'default-roles-ci0-realm.json',  # not in RH SSO 7.4
        ]
        if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_5:
            expected_files.append("default-roles-ci0-realm.json")
            # TODO fix for 7.4
        assert unordered(os.listdir(datadir)) == expected_files

        data = json.load(open(os.path.join(datadir, "ci0-role-0.json")))
        assert list(data.keys()) == [
            'attributes',
            'clientRole',
            'composite',
            'description',
            'name',
        ]
        assert data["name"] == "ci0-role-0"
        assert data["clientRole"] is False
        assert data["composite"] is False
        assert data["attributes"] == {"ci0-role-0-key0": ["ci0-role-0-value0"]}

        data = json.load(open(os.path.join(datadir, "ci0-role-1.json")))
        assert list(data.keys()) == [
            'attributes',
            'clientRole',
            'composite',
            'composites',
            'description',
            'name',
        ]
        assert data["name"] == "ci0-role-1"
        assert data["clientRole"] is False
        assert data["composite"] is True
        assert data["attributes"] == {"ci0-role-1-key0": ["ci0-role-1-value0"]}
        assert len(data["composites"]) == 3
        #
        composites_sorted = sorted(data["composites"], key=lambda obj: obj["name"])
        assert list(composites_sorted[0].keys()) == [
            'clientRole',
            # 'composite',
            'containerName',
            # 'description',
            'name',
        ]
        # check only important attributes.
        assert composites_sorted[0]["clientRole"] is True
        assert composites_sorted[0]["containerName"] == "ci0-client-0"
        assert composites_sorted[0]["name"] == "ci0-client0-role1a"
        #
        assert composites_sorted[1]["clientRole"] is False
        assert composites_sorted[1]["containerName"] == "ci0-realm"
        assert composites_sorted[1]["name"] == "ci0-role-1a"
        #
        assert composites_sorted[2]["clientRole"] is False
        assert composites_sorted[2]["containerName"] == "ci0-realm"
        assert composites_sorted[2]["name"] == "ci0-role-1b"

import glob

from pytest import mark
import json
import os

from pytest_unordered import unordered

from kcfetcher.fetch import GroupFetch
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login


@mark.vcr()
class TestGroupFetch_vcr:
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
        resource_name = "groups"
        resource_identifier = "name"

        obj = GroupFetch(kc, resource_name, resource_identifier, realm_name)

        obj.fetch(store_api)

        # check generated content
        assert unordered(glob.glob('**', root_dir=datadir, recursive=True)) == [
            'ci0-group.json',
            'ci0-group-1a.json',
        ]

        # ci0-group group has one realm role
        data = json.load(open(os.path.join(datadir, "ci0-group.json")))
        assert data == {
            "access": {
                "manage": True,
                "manageMembership": True,
                "view": True
            },
            "attributes": {
                "ci0-group-key0": [
                    "ci0-group-value0"
                ]
            },
            "clientRoles": {},
            "name": "ci0-group",
            "path": "/ci0-group",
            "realmRoles": [
                "ci0-role-0"
            ],
            "subGroups": []
        }

        # ci0-group-1a group has nested child groups
        data = json.load(open(os.path.join(datadir, "ci0-group-1a.json")))
        assert data == {
            "access": {
                "manage": True,
                "manageMembership": True,
                "view": True
            },
            "attributes": {
                "ci0-group-1a-key0": [
                    "ci0-group-1a-value0"
                ]
            },
            "clientRoles": {},
            "name": "ci0-group-1a",
            "path": "/ci0-group-1a",
            "realmRoles": [],
            "subGroups": [
                {
                    "attributes": {},
                    "clientRoles": {},
                    "name": "ci0-group-1b",
                    "path": "/ci0-group-1a/ci0-group-1b",
                    "realmRoles": [],
                    "subGroups": [
                        {
                            "attributes": {},
                            "clientRoles": {},
                            "name": "ci0-group-1c",
                            "path": "/ci0-group-1a/ci0-group-1b/ci0-group-1c",
                            "realmRoles": [],
                            "subGroups": []
                        }
                    ]
                }
            ]
        }

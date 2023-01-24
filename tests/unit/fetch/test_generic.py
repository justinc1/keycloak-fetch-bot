from pytest import mark
import json
import os
import shutil
from kcfetcher.fetch import GenericFetch
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder


class TestGenericFetch:
    # @mark.parametrize(
    #     "resource_name, expected_fetch_class",
    #     [
    #         ("components", GenericFetch),
    #         ("authentication", CustomAuthenticationFetch),
    #         ("clients", ClientFetch),
    #         ("random-mock-resource-name", GenericFetch),
    #     ]
    # )
    # def test_create(self, resource_name, expected_fetch_class):
    def test_fetch(self, mocker):
        outd = "output/ci/TestGenericFetch"
        remove_folder(outd)
        store = Store(outd)
        kc = "mykc"
        realm = "myrealm"
        # resource_name, resource_id = ("components", "name")
        # resource_name, resource_id = ("identity-provider", "alias")
        resource_name, resource_id = ("clients", "clientId")
        mock_data = [  # clients
            {
                "clientId": "master-realm",
                "name": "master Realm",
                "alwaysDisplayInConsole": False,
                "attributes": {},
            },
            {
                "clientId": "my-realm-1",
                "name": "My Realm 1",
                "alwaysDisplayInConsole": False,
                "attributes": {},
            },
        ]

        fetcher = GenericFetch(kc, resource_name, resource_id, realm)
        mocker.patch.object(fetcher, '_get_data', return_value=mock_data)
        fetcher.fetch(store)

        assert mock_data[0] == json.load(open(os.path.join(outd, "master-realm.json")))
        assert mock_data[1] == json.load(open(os.path.join(outd, "my-realm-1.json")))

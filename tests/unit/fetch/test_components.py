from operator import itemgetter

from pytest import mark
from pytest_unordered import unordered
import json
import os
import shutil
from kcfetcher.fetch import ComponentFetch
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login


@mark.vcr()
class TestComponentFetch:
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
        resource_name = "components"
        resource_identifier = "name"
        obj = ComponentFetch(kc, resource_name, resource_identifier, realm_name)

        obj.fetch(store_api)

        # check generated content
        print(os.listdir(datadir))
        assert os.listdir(datadir) == unordered([
            "consent_required.json",
            "max_clients_limit.json",
            "full_scope_disabled.json",
            "allowed_protocol_mapper_types.json",
            "trusted_hosts.json",
            "rsa-generated.json",
            "aes-generated.json",
            "rsa-enc-generated.json",
            "hmac-generated.json",
            "allowed_client_scopes.json",
        ])

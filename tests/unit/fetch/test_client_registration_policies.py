import glob
from operator import itemgetter

from pytest import mark
from pytest_unordered import unordered
import json
import os
import shutil
from kcfetcher.fetch import ClientRegistrationPolicyFetch
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login
from kcfetcher.utils.helper import RH_SSO_VERSIONS_7_5


@mark.vcr()
class TestClientRegistrationPolicyFetch:
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
        resource_name = "client-registration-policies"
        resource_identifier = "name"
        obj = ClientRegistrationPolicyFetch(kc, resource_name, resource_identifier, realm_name)

        obj.fetch(store_api)

        # check generated content
        assert unordered(glob.glob('**', root_dir=datadir, recursive=True)) == [
            "anonymous",
            "anonymous/consent_required.json",
            "anonymous/max_clients_limit.json",
            "anonymous/full_scope_disabled.json",
            "anonymous/allowed_protocol_mapper_types.json",
            "anonymous/trusted_hosts.json",
            "anonymous/allowed_client_scopes.json",

            "authenticated",
            "authenticated/allowed_protocol_mapper_types.json",
            "authenticated/allowed_client_scopes.json",
        ]

from pytest import mark
import json
import os
import shutil
from kcfetcher.fetch import UserFetch
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login


@mark.vcr()
class TestUserFetch_vcr:
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
        resource_name = "users"
        resource_identifier = "username"

        obj = UserFetch(kc, resource_name, resource_identifier, realm_name)

        obj.fetch(store_api)

        # check generated content
        assert os.listdir(datadir) == ["ci0-user.json"]
        #
        data = json.load(open(os.path.join(datadir, "ci0-user.json")))
        assert list(data.keys()) == [
            'access',
            'attributes',
            'createdTimestamp',
            'disableableCredentialTypes',
            'emailVerified',
            'enabled',
            'firstName',
            'groups',
            'lastName',
            'notBefore',
            'requiredActions',
            'totp',
            'username',
        ]
        assert data["username"] == "ci0-user"
        assert data["groups"] == ["ci0-group"]


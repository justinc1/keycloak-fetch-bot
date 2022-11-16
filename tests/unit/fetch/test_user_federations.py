from operator import itemgetter

from pytest import mark
from pytest_unordered import unordered
from path import glob
import json
import os
import shutil
from kcfetcher.fetch import UserFederationFetch
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login


@mark.vcr()
class TestUserFederationFetch:
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
        resource_name = "user-federations"
        resource_identifier = "name"
        obj = UserFederationFetch(kc, resource_name, resource_identifier, realm_name)

        obj.fetch(store_api)

        # check generated content
        assert unordered(glob.glob('**', root_dir=datadir, recursive=True)) == [
            'ci0-uf0-ldap',
            'ci0-uf0-ldap/ci0-uf0-ldap.json',
            'ci0-uf0-ldap/mappers',
            'ci0-uf0-ldap/mappers/creation_date.json',
            'ci0-uf0-ldap/mappers/email.json',
            'ci0-uf0-ldap/mappers/first_name.json',
            'ci0-uf0-ldap/mappers/last_name.json',
            'ci0-uf0-ldap/mappers/modify_date.json',
            'ci0-uf0-ldap/mappers/username.json',

            'ci0-uf1-ldap',
            'ci0-uf1-ldap/ci0-uf1-ldap.json',
            'ci0-uf1-ldap/mappers',
            'ci0-uf1-ldap/mappers/creation_date.json',
            'ci0-uf1-ldap/mappers/email.json',
            'ci0-uf1-ldap/mappers/first_name.json',
            'ci0-uf1-ldap/mappers/last_name.json',
            'ci0-uf1-ldap/mappers/modify_date.json',
            'ci0-uf1-ldap/mappers/username.json',
        ]

        data = json.load(open(os.path.join(datadir, "ci0-uf0-ldap/ci0-uf0-ldap.json")))
        assert list(data.keys()) == [
            'config',
            'name',
            'parentId',
            'providerId',
            'providerType',
        ]
        assert list(data["config"].keys()) == [
            'allowKerberosAuthentication',
            'authType',
            'batchSizeForSync',
            'bindCredential',
            'bindDn',
            'cachePolicy',
            'changedSyncPeriod',
            'connectionPooling',
            'connectionUrl',
            'debug',
            'enabled',
            'fullSyncPeriod',
            'importEnabled',
            'pagination',
            'priority',
            'rdnLDAPAttribute',
            'searchScope',
            'syncRegistrations',
            'trustEmail',
            'useKerberosForPasswordAuthentication',
            'useTruststoreSpi',
            'userObjectClasses',
            'usernameLDAPAttribute',
            'usersDn',
            'uuidLDAPAttribute',
            'validatePasswordPolicy',
            'vendor',
        ]
        assert data["name"] == "ci0-uf0-ldap"
        assert data["config"]["connectionUrl"] == ["ldaps://172.17.0.4:636"]

        # check attribute mappers
        mapper = json.load(open(os.path.join(datadir, "ci0-uf0-ldap/mappers/email.json")))
        assert list(mapper.keys()) == [
            'config',
            'name',
            'providerId',
            'providerType',
        ]
        assert mapper["name"] == "email"
        assert mapper["providerId"] == "user-attribute-ldap-mapper"
        assert mapper["providerType"] == "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
        assert len(mapper["config"]) == 5
        assert mapper["config"]["ldap.attribute"] == ["mail"]
        assert mapper["config"]["user.model.attribute"] == ["email"]

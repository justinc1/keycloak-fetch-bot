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
            "last_name.json",
            "consent_required.json",
            "max_clients_limit.json",
            "full_scope_disabled.json",
            "modify_date.json",
            "allowed_protocol_mapper_types.json",
            "trusted_hosts.json",
            "first_name.json",
            "rsa-generated.json",
            "username.json",
            "ci0-uf0-ldap.json",
            "aes-generated.json",
            "rsa-enc-generated.json",
            "creation_date.json",
            "hmac-generated.json",
            "allowed_client_scopes.json",
            "ci0-uf1-ldap.json",
        ])
        return

        assert os.listdir(os.path.join(datadir, "ci0-uf0-ldap")) == unordered(["ci0-uf0-ldap.json", "mappers"])
        assert os.listdir(os.path.join(datadir, "ci0-uf0-ldap/mappers")) == unordered(["mappers.json"])
        assert os.listdir(os.path.join(datadir, "ci0-uf1-ldap")) == unordered(["ci0-uf1-ldap.json", "mappers"])
        assert os.listdir(os.path.join(datadir, "ci0-uf1-ldap/mappers")) == unordered(["mappers.json"])
        #
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
        data = json.load(open(os.path.join(datadir, "ci0-uf0-ldap/mappers/mappers.json")))
        assert len(data) == 6
        assert list(data[0].keys()) == [
            'config',
            'name',
            'providerId',
            'providerType',
        ]
        assert data[0]["providerId"] == "user-attribute-ldap-mapper"
        assert data[0]["providerType"] == "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
        assert len(data[0]["config"]) == 5
        # sort by name, to have predictable order
        data_sorted = sorted(data, key=itemgetter("name"))
        assert data_sorted[1]["config"]["ldap.attribute"] == ["mail"]
        assert data_sorted[1]["config"]["user.model.attribute"] == ["email"]

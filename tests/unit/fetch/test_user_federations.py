from operator import itemgetter

from pytest import mark
from pytest_unordered import unordered
from path import glob
import json
import os
import shutil
from kcfetcher.fetch import UserFederationFetch
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login,  find_in_list


class TestUserFederationFetchBase:
    def get_fetcher(self):
        server = os.environ["SSO_API_URL"]
        user = os.environ["SSO_API_USERNAME"]
        password = os.environ["SSO_API_PASSWORD"]
        kc = login(server, user, password)

        realm_name = "ci0-realm"
        resource_name = "user-federations"
        resource_identifier = "name"
        return UserFederationFetch(kc, resource_name, resource_identifier, realm_name)

class TestUserFederationFetch(TestUserFederationFetchBase):
    @mark.vcr()
    def test_fetch(self):
        datadir = "output/ci/outd"
        remove_folder(datadir)
        make_folder(datadir)
        store_api = Store(datadir)
        fetcher = self.get_fetcher()

        fetcher.fetch(store_api)

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
            'ci0-uf0-ldap/mappers/ci0-uf0-mapper-0-user-attr.json',

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
        assert data == {
            "config": {
                "allowKerberosAuthentication": [
                    "false"
                ],
                "authType": [
                    "simple"
                ],
                "batchSizeForSync": [
                    "1000"
                ],
                "bindCredential": [
                    "**********"
                ],
                "bindDn": [
                    "admin"
                ],
                "cachePolicy": [
                    "DEFAULT"
                ],
                "changedSyncPeriod": [
                    "-1"
                ],
                "connectionPooling": [
                    "true"
                ],
                "connectionUrl": [
                    "ldaps://172.17.0.4:636"
                ],
                "debug": [
                    "false"
                ],
                "enabled": [
                    "true"
                ],
                "fullSyncPeriod": [
                    "-1"
                ],
                "importEnabled": [
                    "true"
                ],
                "pagination": [
                    "true"
                ],
                "priority": [
                    "0"
                ],
                "rdnLDAPAttribute": [
                    "uid"
                ],
                "searchScope": [
                    "1"
                ],
                "syncRegistrations": [
                    "false"
                ],
                "trustEmail": [
                    "false"
                ],
                "useKerberosForPasswordAuthentication": [
                    "false"
                ],
                "useTruststoreSpi": [
                    "ldapsOnly"
                ],
                "userObjectClasses": [
                    "inetOrgPerson, organizationalPerson"
                ],
                "usernameLDAPAttribute": [
                    "uid"
                ],
                "usersDn": [
                    "uid"
                ],
                "uuidLDAPAttribute": [
                    "nsuniqueid"
                ],
                "validatePasswordPolicy": [
                    "false"
                ],
                "vendor": [
                    "rhds"
                ]
            },
            "name": "ci0-uf0-ldap",
            "parentName": "ci0-realm",
            "providerId": "ldap",
            "providerType": "org.keycloak.storage.UserStorageProvider"
        }

        # check attribute mappers
        mapper = json.load(open(os.path.join(datadir, "ci0-uf0-ldap/mappers/email.json")))
        assert mapper == {
            "config": {
                "always.read.value.from.ldap": [
                    "false"
                ],
                "is.mandatory.in.ldap": [
                    "false"
                ],
                "ldap.attribute": [
                    "mail"
                ],
                "read.only": [
                    "true"
                ],
                "user.model.attribute": [
                    "email"
                ]
            },
            "name": "email",
            "providerId": "user-attribute-ldap-mapper",
            "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
        }

        # check custom attribute mapper
        mapper = json.load(open(os.path.join(datadir, "ci0-uf0-ldap/mappers/ci0-uf0-mapper-0-user-attr.json")))
        assert mapper == {
            "config": {
                "always.read.value.from.ldap": [
                    "true"
                ],
                "is.binary.attribute": [
                    "true"
                ],
                "is.mandatory.in.ldap": [
                    "false"
                ],
                "ldap.attribute": [
                    "ci-ldap-attr"
                ],
                "read.only": [
                    "true"
                ],
                "user.model.attribute": [
                    "ci-user-model-attr"
                ]
            },
            "name": "ci0-uf0-mapper-0-user-attr",
            "providerId": "user-attribute-ldap-mapper",
            "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
        }

    @mark.vcr()
    def test_get_all_mappers(self):
        fetcher = self.get_fetcher()

        components_api = fetcher.kc.build("components", fetcher.realm)
        all_components = components_api.all()
        # We want to get mappers of a single specific user federation.
        # The user federation is identified by id, so get that id.
        uf_name = "ci0-uf0-ldap"
        uf_id = find_in_list(all_components, name=uf_name)["id"]

        mappers = fetcher.get_all_mappers(all_components, [uf_id])

        assert len(mappers) == 7
        mapper = find_in_list(mappers, name="email")
        assert mapper["name"] == "email"
        assert mapper["providerId"] == "user-attribute-ldap-mapper"
        assert mapper["providerType"] == "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"

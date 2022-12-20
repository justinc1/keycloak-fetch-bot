import glob

from pytest import mark
from pytest_unordered import unordered
import json
import os
from kcfetcher.fetch import ClientFetch
from kcfetcher.store import Store
from kcfetcher.utils import remove_folder, make_folder, login, RH_SSO_VERSIONS_7_4, RH_SSO_VERSIONS_7_5


@mark.vcr()
class TestClientFetch_vcr:
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
        resource_name = "clients"
        resource_identifier = "clientId"

        obj = ClientFetch(kc, resource_name, resource_identifier, realm_name)

        obj.fetch(store_api)

        # check generated content
        assert unordered(glob.glob('**', root_dir=datadir, recursive=True)) == [
            'client-0',
            'client-0/roles',
            'client-0/roles/ci0-client0-role1.json',
            'client-0/roles/ci0-client0-role0.json',
            'client-0/roles/ci0-client0-role1b.json',
            'client-0/roles/ci0-client0-role1a.json',
            'client-0/ci0-client-0.json',
            'client-0/scope-mappings.json',

            'client-1',
            'client-1/roles',
            'client-1/roles/ci0-client1-role0.json',
            'client-1/ci0-client-1.json',
            'client-1/scope-mappings.json',

            'client-2',
            'client-2/roles',
            'client-2/roles/ci0-client2-role0.json',
            'client-2/ci0-client-2-saml.json',
            'client-2/scope-mappings.json',

            'client-3',
            'client-3/ci0-client-3-saml.json',
            'client-3/scope-mappings.json',
        ]

        # =======================================================================================
        data = json.load(open(os.path.join(datadir, "client-0/ci0-client-0.json")))
        expected_attrs = [
            'access',
            'alwaysDisplayInConsole',
            'attributes',
            'authenticationFlowBindingOverrides',
            'bearerOnly',
            'clientAuthenticatorType',
            'clientId',
            'consentRequired',
            'defaultClientScopes',
            # 'defaultRoles',  # RH SSO 7.4
            'description',
            'directAccessGrantsEnabled',
            'enabled',
            'frontchannelLogout',
            'fullScopeAllowed',
            'implicitFlowEnabled',
            'name',  # ci0-client-0 has name
            'nodeReRegistrationTimeout',
            'notBefore',
            'optionalClientScopes',
            'protocol',
            'protocolMappers',
            'publicClient',
            'redirectUris',
            'serviceAccountsEnabled',
            'standardFlowEnabled',
            'surrogateAuthRequired',
            'webOrigins',
        ]
        if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_4:
            expected_attrs += ['defaultRoles']
        assert list(data.keys()) == unordered(expected_attrs)
        assert data["clientId"] == "ci0-client-0"
        assert data["name"] == "ci0-client-0-name"
        assert data["clientAuthenticatorType"] == "client-secret"
        expected_defaultClientScopes = [
            'ci0-client-scope',
            'email',
            'profile',
            'role_list',
            'roles',
            'web-origins',
        ]
        if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_5:
            # remove "role_list"
            assert "role_list" == expected_defaultClientScopes.pop(3)
        assert data["defaultClientScopes"] == expected_defaultClientScopes
        assert data["optionalClientScopes"] == [
            'address',
            'phone',
            'offline_access',
            'microprofile-jwt',
        ]

        if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_4:
            assert data["defaultRoles"] == ["ci0-client0-role0"]

        # authenticationFlowBindingOverrides must contain names, not UUIDs
        assert isinstance(data["authenticationFlowBindingOverrides"], dict)
        assert list(data["authenticationFlowBindingOverrides"].keys()) == ["browser"]
        assert data["authenticationFlowBindingOverrides"]["browser"] == "browser"

        # protocolMappers are present only if they are not an empty list
        assert data["protocolMappers"] == unordered([
            {
                "config": {
                    "access.token.claim": "true",
                    "claim.name": "gender",
                    "id.token.claim": "true",
                    "jsonType.label": "String",
                    "user.attribute": "gender",
                    "userinfo.token.claim": "true"
                },
                "consentRequired": False,
                "name": "gender",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-attribute-mapper"
            },
            {
                "config": {
                    "access.token.claim": "true",
                    "claim.name": "ci-claim-name",
                    "id.token.claim": "true",
                    "jsonType.label": "String",
                    "user.attribute": "ci-user-property-name",
                    "userinfo.token.claim": "true"
                },
                "consentRequired": False,
                "name": "ci0-client0-mapper-1",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-property-mapper"
            },
        ])

        # =======================================================================================
        # Check client scope mappings
        data_unsorted = json.load(open(os.path.join(datadir, "client-0/scope-mappings.json")))
        data = sorted(data_unsorted, key=lambda obj: obj["name"])
        assert isinstance(data, list)
        assert len(data) == 3

        assert list(data[0].keys()) == [
            'clientRole',
            'containerName',
            'name',
        ]

        assert data[0]["name"] == "ci0-client1-role0"
        assert data[0]["clientRole"] is True
        assert data[0]["containerName"] == "ci0-client-1"

        assert data[1]["name"] == "ci0-role-0"
        assert data[1]["clientRole"] is False
        assert data[1]["containerName"] == "ci0-realm"

        assert data[2]["name"] == "ci0-role-1b"
        assert data[2]["clientRole"] is False
        assert data[2]["containerName"] == "ci0-realm"

        # =======================================================================================
        # Check client role
        role = json.load(open(os.path.join(datadir, "client-0/roles/ci0-client0-role0.json")))
        assert list(role.keys()) == [
            'attributes',
            'clientRole',
            'composite',
            # containerId UUID - clientId, it MUST be removed.
            # The parent client clientId will be derived from roles.json filepath.
            # 'containerId',
            'description',
            'name',
        ]
        assert role["name"] == "ci0-client0-role0"
        assert role["description"] == "ci0-client0-role0-desc"
        assert role["clientRole"] is True
        assert role["composite"] is False
        assert role["attributes"] == {"ci0-client0-role0-key0": ["ci0-client0-role0-value0"]}

        role = json.load(open(os.path.join(datadir, "client-0/roles/ci0-client0-role1.json")))
        assert list(role.keys()) == [
            'attributes',
            'clientRole',
            'composite',
            'composites',
            # 'containerId',
            'description',
            'name',
        ]
        assert role["name"] == "ci0-client0-role1"
        assert role["description"] == "ci0-client0-role1-desc"
        assert role["clientRole"] is True
        assert role["composite"] is True
        assert role["attributes"] == {"ci0-client0-role1-key0": ["ci0-client0-role1-value0"]}
        assert len(role["composites"]) == 3
        #
        composites_sorted = sorted(role["composites"], key=lambda obj: obj["name"])
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
        assert composites_sorted[1]["clientRole"] is True
        assert composites_sorted[1]["containerName"] == "ci0-client-0"
        assert composites_sorted[1]["name"] == "ci0-client0-role1b"
        #
        assert composites_sorted[2]["clientRole"] is False
        assert composites_sorted[2]["containerName"] == "ci0-realm"
        assert composites_sorted[2]["name"] == "ci0-role-1a"

        # =======================================================================================
        data = json.load(open(os.path.join(datadir, "client-1/ci0-client-1.json")))
        assert list(data.keys()) == [
            'access',
            'alwaysDisplayInConsole',
            'attributes',
            'authenticationFlowBindingOverrides',
            'bearerOnly',
            'clientAuthenticatorType',
            'clientId',
            'consentRequired',
            'defaultClientScopes',
            'description',
            'directAccessGrantsEnabled',
            'enabled',
            'frontchannelLogout',
            'fullScopeAllowed',
            'implicitFlowEnabled',
            # 'name',  # ci0-client-1 does not have a name set, so it is not in json file
            'nodeReRegistrationTimeout',
            'notBefore',
            'optionalClientScopes',
            'protocol',
            # 'protocolMappers',  # was not configured for ci0-client-1
            'publicClient',
            'redirectUris',
            'serviceAccountsEnabled',
            'standardFlowEnabled',
            'surrogateAuthRequired',
            'webOrigins',
        ]
        assert data["clientId"] == "ci0-client-1"
        assert data["clientAuthenticatorType"] == "client-secret"
        expected_defaultClientScopes = [
            'email',
            'profile',
            'role_list',
            'roles',
            'web-origins',
        ]
        if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_5:
            # remove "role_list"
            assert "role_list" == expected_defaultClientScopes.pop(2)
        assert data["defaultClientScopes"] == expected_defaultClientScopes
        assert data["optionalClientScopes"] == [
            'address',
            'phone',
            'offline_access',
            'microprofile-jwt',
        ]

        # =======================================================================================
        data = json.load(open(os.path.join(datadir, "client-2/ci0-client-2-saml.json")))
        if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_4:
            assert data["defaultClientScopes"] == [
                'ci0-client-scope-2-saml',
                'email',
                'profile',
                'role_list',
                'roles',
                'web-origins',
            ]
            assert data["optionalClientScopes"] == [
                'address',
                'phone',
                'offline_access',
                'microprofile-jwt',
            ]
        else:
            # RH SSO 7.5
            assert data["defaultClientScopes"] == [
                'ci0-client-scope-2-saml',
                'role_list',
            ]
            assert data["optionalClientScopes"] == []
            assert 'saml.artifact.binding.identifier' in data["attributes"]
            assert isinstance( data["attributes"]["saml.artifact.binding.identifier"], str)
            data["attributes"].pop("saml.artifact.binding.identifier")
        data.pop("defaultClientScopes")
        data.pop("optionalClientScopes")

        assert data == {
            'access': {'configure': True, 'manage': True, 'view': True},
            'adminUrl': 'http://ci0-client-2-saml-admin-url.example.com',
            'alwaysDisplayInConsole': False,
            'attributes': {
                # 'saml.artifact.binding.identifier': ""  # RHSSO 7.5 only
                'saml.assertion.lifespan': '120',
                'saml.authnstatement': 'true',
                'saml.client.signature': 'true',
                'saml.force.post.binding': 'true',
                'saml.server.signature': 'true',
                'saml.signature.algorithm': 'RSA_SHA256',
                # 'saml.signing.certificate': 'MIICsTCC...',
                # 'saml.signing.private.key': 'MIIEowIB...',
                'saml_assertion_consumer_url_post': 'http://saml-admin-url-post.example.com',
                'saml_force_name_id_format': 'false',
                'saml_name_id_format': 'username',
                'saml_signature_canonicalization_method': 'http://www.w3.org/2001/10/xml-exc-c14n#',
            },
            'authenticationFlowBindingOverrides': {'browser': 'browser'},
            'bearerOnly': False,
            'clientAuthenticatorType': 'client-secret',
            'clientId': 'ci0-client-2-saml',
            'consentRequired': False,
            # 'defaultClientScopes': [...]
            'description': 'ci0-client-2-saml-desc',
            'directAccessGrantsEnabled': False,
            'enabled': True,
            'frontchannelLogout': True,
            'fullScopeAllowed': False,
            'implicitFlowEnabled': False,
            'name': 'ci0-client-2-saml-name',
            'nodeReRegistrationTimeout': -1,
            'notBefore': 0,
            # 'optionalClientScopes': [...]
            'protocol': 'saml',
            'protocolMappers': [
                {
                    "name": "X500 email",
                    "protocol": "saml",
                    "protocolMapper": "saml-user-property-mapper",
                    "consentRequired": False,
                    "config": {
                        "attribute.nameformat": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                        "user.attribute": "email",
                        "friendly.name": "email",
                        "attribute.name": "urn:oid:1.2.840.113549.1.9.1",
                    },
                },
                {
                    "protocol": "saml",
                    "config": {
                        "Script": "/**/\n//insert your code here...",
                        "single": "true",
                        "friendly.name": "ci0-client-2-saml-mapper-js-friedly",
                        "attribute.name": "ci0-client-2-saml-mapper-attr-name",
                        "attribute.nameformat": "Basic",
                    },
                    "consentRequired": False,
                    "name": "ci0-client-2-saml-mapper-js",
                    "protocolMapper": "saml-javascript-mapper",
                },
            ],
            'publicClient': False,
            'redirectUris': [
                'https://ci0-client-2-saml.example.com/redirect-url',
            ],
            'serviceAccountsEnabled': False,
            'standardFlowEnabled': True,
            'surrogateAuthRequired': False,
            'webOrigins': [
                'https://ci0-client-2-saml.example.com',
            ],
        }

        data = json.load(open(os.path.join(datadir, "client-2/scope-mappings.json")))
        assert data == [
            {
                "clientRole": True,
                "containerName": "ci0-client-0",
                "name": "ci0-client0-role1",
            },
            {
                "clientRole": False,
                "containerName": "ci0-realm",
                "name": "ci0-role-1a",
            },
        ]

        data = json.load(open(os.path.join(datadir, "client-2/roles/ci0-client2-role0.json")))
        assert data == {
            "attributes": {
                "ci0-client2-role0-key0": [
                    "ci0-client2-role0-value0"
                ]
            },
            "clientRole": True,
            "composite": False,
            "description": "ci0-client2-role0-desc",
            "name": "ci0-client2-role0"
        }

        # =======================================================================================
        # A default, unconfigured SAML client
        data = json.load(open(os.path.join(datadir, "client-3/ci0-client-3-saml.json")))
        if kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_4:
            assert data["defaultClientScopes"] == [
                'email',
                'profile',
                'role_list',
                'roles',
                'web-origins',
            ]
            assert data["optionalClientScopes"] == [
                'address',
                'phone',
                'offline_access',
                'microprofile-jwt',
            ]
        else:
            # RH SSO 7.5
            assert data["defaultClientScopes"] == [
                'role_list',
            ]
            assert data["optionalClientScopes"] == []
            assert 'saml.artifact.binding.identifier' in data["attributes"]
            assert isinstance( data["attributes"]["saml.artifact.binding.identifier"], str)
            data["attributes"].pop("saml.artifact.binding.identifier")
        data.pop("defaultClientScopes")
        data.pop("optionalClientScopes")

        assert data == {
             'access': {'configure': True, 'manage': True, 'view': True},
             'adminUrl': 'http://ci0-client-3-saml-admin-url.example.com',
             'alwaysDisplayInConsole': False,
             'attributes': {'saml.authnstatement': 'true',
                            'saml.client.signature': 'true',
                            'saml.force.post.binding': 'true',
                            'saml.server.signature': 'true',
                            'saml.signature.algorithm': 'RSA_SHA256',
                            'saml_force_name_id_format': 'false',
                            'saml_name_id_format': 'username',
                            'saml_signature_canonicalization_method': 'http://www.w3.org/2001/10/xml-exc-c14n#'},
             'authenticationFlowBindingOverrides': {},
             'bearerOnly': False,
             'clientAuthenticatorType': 'client-secret',
             'clientId': 'ci0-client-3-saml',
             'consentRequired': False,
             # 'defaultClientScopes': [...],
             'directAccessGrantsEnabled': False,
             'enabled': True,
             'frontchannelLogout': True,
             'fullScopeAllowed': True,
             'implicitFlowEnabled': False,
             'nodeReRegistrationTimeout': -1,
             'notBefore': 0,
             # 'optionalClientScopes': [...],
             'protocol': 'saml',
             'publicClient': False,
             'redirectUris': [],
             'serviceAccountsEnabled': False,
             'standardFlowEnabled': True,
             'surrogateAuthRequired': False,
             'webOrigins': []
             }

        data = json.load(open(os.path.join(datadir, "client-3/scope-mappings.json")))
        assert data == []

import json
import os
import shutil
from kcfetcher.utils.helper import remove_ids, normalize, sort_json
# from tests.integration.test_ping import BaseTestClass
from pytest import mark


class Test_remove_ids:
    @mark.parametrize(
        "kc_object, expected_obj",
        [
            ({}, {}),
            # already clean, simple dict
            (
                {"k1": "v1"},
                {"k1": "v1"},
            ),
            (
                {"k1": "v1", "k2": "v2"},
                {"k1": "v1", "k2": "v2"},
            ),
            # already clean, dict with subdict and sublist
            (
                {"k1": "v1", "subd": {"k3": "v3"}, "subl": [{"subl1-k": "subl1-v"}, {"subl2-k": "subl2-v"}]},
                {"k1": "v1", "subd": {"k3": "v3"}, "subl": [{"subl1-k": "subl1-v"}, {"subl2-k": "subl2-v"}]},
            ),
            # with id/flowId, simple dict
            (
                {"id": "id-v"},
                {},
            ),
            (
                {"k1": "v1", "id": "id-v"},
                {"k1": "v1"},
            ),
            (
                {"k1": "v1", "flowId": "fid-v"},
                {"k1": "v1"},
            ),
            # order in dict should not matter, but test this anyway
            (
                {"id": "id-v", "k1": "v1"},
                {"k1": "v1"},
            ),
            # with id/flowId, dict with subdict and sublist
            (
                {"id": "id-v", "subd": {"k3": "v3"}, "subl": [{"subl1-k": "subl1-v"}, {"subl2-k": "subl2-v"}]},
                {"subd": {"k3": "v3"}, "subl": [{"subl1-k": "subl1-v"}, {"subl2-k": "subl2-v"}]},
            ),
            (
                {"k1": "v1", "subd": {"k3": "v3", "id": "id-v"}, "subl": [{"subl1-k": "subl1-v"}, {"subl2-k": "subl2-v"}]},
                {"k1": "v1", "subd": {"k3": "v3"}, "subl": [{"subl1-k": "subl1-v"}, {"subl2-k": "subl2-v"}]},
            ),
            (
                {"k1": "v1", "subd": {"k3": "v3"}, "subl": [{"subl1-k": "subl1-v", "id": "id-v"}, {"subl2-k": "subl2-v"}]},
                {"k1": "v1", "subd": {"k3": "v3"}, "subl": [{"subl1-k": "subl1-v"}, {"subl2-k": "subl2-v"}]},
            ),
            (
                {"k1": "v1", "subd": {"k3": "v3"}, "subl": [{"subl1-k": "subl1-v"}, {"subl2-k": "subl2-v", "id": "id-v"}]},
                {"k1": "v1", "subd": {"k3": "v3"}, "subl": [{"subl1-k": "subl1-v"}, {"subl2-k": "subl2-v"}]},
            ),
            (
                {"k1": "v1", "subd": {"k3": "v3"}, "subl": [{"subl1-k": "subl1-v"}, {"subl2-k": "subl2-v", "id": "id-v"}]},
                {"k1": "v1", "subd": {"k3": "v3"}, "subl": [{"subl1-k": "subl1-v"}, {"subl2-k": "subl2-v"}]},
            ),
            # and something with flowId
            (
                {"k1": "v1", "flowId": "fid-v1", "subd": {"k3": "v3"}, "subl": [{"subl1-k": "subl1-v"}, {"subl2-k": "subl2-v", "flowId": "fid-v2"}]},
                {"k1": "v1", "subd": {"k3": "v3"}, "subl": [{"subl1-k": "subl1-v"}, {"subl2-k": "subl2-v"}]},
            ),
        ]
    )
    def test_remove_ids(self, kc_object, expected_obj):
        obj = remove_ids(kc_object)
        assert expected_obj == obj

    @mark.parametrize(
        "kc_object, expected_obj",
        [
            ({}, {}),
            (
                {"k1": "v1", "id": "id-v"},
                {"k1": "v1"},
            ),
        ]
    )
    def test_returned_object_is_new(self, kc_object, expected_obj):
        """
        We often referr same object multipletimes.
        Removing say "name" attribute needs to return a copy of object.
        """
        obj = remove_ids(kc_object)
        assert expected_obj == obj
        assert id(expected_obj) != id(obj)
        # modify input, output must not change
        obj.update({"new-key": "new-value"})
        assert "new-key" not in expected_obj


class Test_normalize:
    @mark.parametrize(
        "identifier_in, expected_identifier",
        [
            ("myident", "myident"),
            ("aa/bb cc=dd,ee", "aa_bb_cc_dd_ee"),
            ("aa/bb cc=dd,ee---aa/bb cc=dd,ee", "aa_bb_cc_dd_ee---aa_bb_cc_dd_ee"),
            ("http://an.url/can.be/a.name-etc", "http___an.url_can.be_a.name-etc"),
            ("username-with-asterix-*", "username-with-asterix-_"),
            ("aa-#-bb", "aa-_-bb"),
            ("aa-/-bb", "aa-_-bb"),
            ("aa-\\-bb", "aa-_-bb"),
        ]
    )
    def test_normalize(self, identifier_in, expected_identifier):
        identifier_out = normalize(identifier_in)
        assert expected_identifier == identifier_out


role_in_abc = {
    "attributes": {
        "ci0-client0-role1-key0": [
            "ci0-client0-role1-value0"
        ]
    },
    "clientRole": True,
    "composite": True,
    "composites": [
        {
            "clientRole": True,
            "containerName": "ci0-client-0",
            "name": "a ci0-client0-role1a"
        },
        {
            "clientRole": True,
            "containerName": "ci0-client-0",
            "name": "b ci0-client0-role1b"
        },
        {
            "clientRole": True,
            "containerName": "ci0-realm",
            "name": "c ci0-role-1a"
        },
    ],
    "description": "ci0-client0-role1-desc",
    "name": "ci0-client0-role1"
}

role_in_bac = {
    "attributes": {
        "ci0-client0-role1-key0": [
            "ci0-client0-role1-value0"
        ]
    },
    "clientRole": True,
    "composite": True,
    "composites": [
        {
            "clientRole": True,
            "containerName": "ci0-client-0",
            "name": "b ci0-client0-role1b"
        },
        {
            "clientRole": True,
            "containerName": "ci0-client-0",
            "name": "a ci0-client0-role1a"
        },
        {
            "clientRole": True,
            "containerName": "ci0-realm",
            "name": "c ci0-role-1a"
        },
    ],
    "description": "ci0-client0-role1-desc",
    "name": "ci0-client0-role1"
}

role_in_acb = {
    "attributes": {
        "ci0-client0-role1-key0": [
            "ci0-client0-role1-value0"
        ]
    },
    "clientRole": True,
    "composite": True,
    "composites": [
        {
            "clientRole": True,
            "containerName": "ci0-client-0",
            "name": "a ci0-client0-role1a"
        },
        {
            "clientRole": True,
            "containerName": "ci0-realm",
            "name": "c ci0-role-1a"
        },
        {
            "clientRole": True,
            "containerName": "ci0-client-0",
            "name": "b ci0-client0-role1b"
        },
    ],
    "description": "ci0-client0-role1-desc",
    "name": "ci0-client0-role1"
}

role_in_cba = {
    "attributes": {
        "ci0-client0-role1-key0": [
            "ci0-client0-role1-value0"
        ]
    },
    "clientRole": True,
    "composite": True,
    "composites": [
        {
            "clientRole": True,
            "containerName": "ci0-realm",
            "name": "c ci0-role-1a"
        },
        {
            "clientRole": True,
            "containerName": "ci0-client-0",
            "name": "b ci0-client0-role1b"
        },
        {
            "clientRole": True,
            "containerName": "ci0-client-0",
            "name": "a ci0-client0-role1a"
        },
    ],
    "description": "ci0-client0-role1-desc",
    "name": "ci0-client0-role1"
}

role_out = {
    "attributes": {
        "ci0-client0-role1-key0": [
            "ci0-client0-role1-value0"
        ]
    },
    "clientRole": True,
    "composite": True,
    "composites": [
        {
            "clientRole": True,
            "containerName": "ci0-client-0",
            "name": "a ci0-client0-role1a"
        },
        {
            "clientRole": True,
            "containerName": "ci0-client-0",
            "name": "b ci0-client0-role1b"
        },
        {
            "clientRole": True,
            "containerName": "ci0-realm",
            "name": "c ci0-role-1a"
        },
    ],
    "description": "ci0-client0-role1-desc",
    "name": "ci0-client0-role1"
}

role_out_attr = {
    "attributes": {
        "aa key": [
            "aa value"
        ],
        "bb key": [
            "bb value"
        ],
        "cc key": [
            "cc value"
        ],
    },
    "clientRole": True,
    "composite": True,
    "composites": [
        {
            "clientRole": True,
            "containerName": "ci0-realm",
            "name": "c ci0-role-1a"
        },
        {
            "clientRole": True,
            "containerName": "ci0-client-0",
            "name": "b ci0-client0-role1b"
        },
        {
            "clientRole": True,
            "containerName": "ci0-client-0",
            "name": "a ci0-client0-role1a"
        },
    ],
    "description": "ci0-client0-role1-desc",
    "name": "ci0-client0-role1"
}
#
# role_in_attr_abc = {
#     "attributes": {
#         "aa key": [
#             "aa value"
#         ],
#         "bb key": [
#             "bb value"
#         ],
#         "cc key": [
#             "cc value"
#         ],
#     },
#     "clientRole": True,
#     "composite": True,
#     "composites": [
#         {
#             "clientRole": True,
#             "containerName": "ci0-realm",
#             "name": "c ci0-role-1a"
#         },
#         {
#             "clientRole": True,
#             "containerName": "ci0-client-0",
#             "name": "b ci0-client0-role1b"
#         },
#         {
#             "clientRole": True,
#             "containerName": "ci0-client-0",
#             "name": "a ci0-client0-role1a"
#         },
#     ],
#     "description": "ci0-client0-role1-desc",
#     "name": "ci0-client0-role1"
# }
#
# role_in_attr_bac = {
#     "attributes": {
#         "bb key": [
#             "bb value"
#         ],
#         "aa key": [
#             "aa value"
#         ],
#         "cc key": [
#             "cc value"
#         ],
#     },
#     "clientRole": True,
#     "composite": True,
#     "composites": [
#         {
#             "clientRole": True,
#             "containerName": "ci0-realm",
#             "name": "c ci0-role-1a"
#         },
#         {
#             "clientRole": True,
#             "containerName": "ci0-client-0",
#             "name": "b ci0-client0-role1b"
#         },
#         {
#             "clientRole": True,
#             "containerName": "ci0-client-0",
#             "name": "a ci0-client0-role1a"
#         },
#     ],
#     "description": "ci0-client0-role1-desc",
#     "name": "ci0-client0-role1"
# }
#
# role_in_attr_acb = {
#     "attributes": {
#         "aa key": [
#             "aa value"
#         ],
#         "cc key": [
#             "cc value"
#         ],
#         "bb key": [
#             "bb value"
#         ],
#     },
#     "clientRole": True,
#     "composite": True,
#     "composites": [
#         {
#             "clientRole": True,
#             "containerName": "ci0-realm",
#             "name": "c ci0-role-1a"
#         },
#         {
#             "clientRole": True,
#             "containerName": "ci0-client-0",
#             "name": "b ci0-client0-role1b"
#         },
#         {
#             "clientRole": True,
#             "containerName": "ci0-client-0",
#             "name": "a ci0-client0-role1a"
#         },
#     ],
#     "description": "ci0-client0-role1-desc",
#     "name": "ci0-client0-role1"
# }
# role_in_attr_cba = {
#     "attributes": {
#         "cc key": [
#             "cc value"
#         ],
#         "bb key": [
#             "bb value"
#         ],
#         "aa key": [
#             "aa value"
#         ],
#     },
#     "clientRole": True,
#     "composite": True,
#     "composites": [
#         {
#             "clientRole": True,
#             "containerName": "ci0-realm",
#             "name": "c ci0-role-1a"
#         },
#         {
#             "clientRole": True,
#             "containerName": "ci0-client-0",
#             "name": "b ci0-client0-role1b"
#         },
#         {
#             "clientRole": True,
#             "containerName": "ci0-client-0",
#             "name": "a ci0-client0-role1a"
#         },
#     ],
#     "description": "ci0-client0-role1-desc",
#     "name": "ci0-client0-role1"
# }
#

# Could be sorted too
# {
#     "config": {
#         "allowed-protocol-mapper-types": [
#             "saml-role-list-mapper",
#             "oidc-full-name-mapper",
#             "oidc-address-mapper",
#             "oidc-usermodel-attribute-mapper",
#             "saml-user-attribute-mapper",
#             "saml-user-property-mapper",
#             "oidc-usermodel-property-mapper",
#             "oidc-sha256-pairwise-sub-mapper"
#         ]
#     },
#     "name": "Allowed Protocol Mapper Types",
#     "parentId": "ci0-realm",
#     "providerId": "allowed-protocol-mappers",
#     "providerType": "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy",
#     "subType": "anonymous"
# }

# allowed protocol mapper types
apm_out = {
    "config": {
        "allowed-protocol-mapper-types": [
            'oidc-address-mapper',
            'oidc-full-name-mapper',
            'oidc-sha256-pairwise-sub-mapper',
            'oidc-usermodel-attribute-mapper',
            'oidc-usermodel-property-mapper',
            'saml-role-list-mapper',
            'saml-user-attribute-mapper',
            'saml-user-property-mapper',
        ]
    },
    "name": "Allowed Protocol Mapper Types",
    "parentId": "ci0-realm",
    "providerId": "allowed-protocol-mappers",
    "providerType": "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy",
    "subType": "authenticated"
}
apm_in_1 = {
    "config": {
        "allowed-protocol-mapper-types": [
            "saml-user-attribute-mapper",
            "saml-user-property-mapper",
            "saml-role-list-mapper",
            "oidc-address-mapper",
            "oidc-usermodel-attribute-mapper",
            "oidc-sha256-pairwise-sub-mapper",
            "oidc-usermodel-property-mapper",
            "oidc-full-name-mapper"
        ]
    },
    "name": "Allowed Protocol Mapper Types",
    "parentId": "ci0-realm",
    "providerId": "allowed-protocol-mappers",
    "providerType": "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy",
    "subType": "authenticated"
}
apm_in_2 = {
    "config": {
        "allowed-protocol-mapper-types": [
            "saml-user-attribute-mapper",
            "saml-user-property-mapper",
            "saml-role-list-mapper",
            "oidc-address-mapper",
            "oidc-usermodel-attribute-mapper",
            "oidc-sha256-pairwise-sub-mapper",
            "oidc-usermodel-property-mapper",
            "oidc-full-name-mapper"
        ]
    },
    "name": "Allowed Protocol Mapper Types",
    "parentId": "ci0-realm",
    "providerId": "allowed-protocol-mappers",
    "providerType": "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy",
    "subType": "authenticated"
}

# sort client defaultClientScopes
dcs_out = {
    "clientId": "ci0-client-0",
    "defaultClientScopes": [
        "email",
        "profile",
        "roles",
        "web-origins",
    ],
    "description": "ci0-client-0-desc",
}
dcs_in_1 = {
    "clientId": "ci0-client-0",
    "defaultClientScopes": [
        "web-origins",
        "profile",
        "roles",
        "email",
    ],
    "description": "ci0-client-0-desc",
}
dcs_in_2 = {
    "clientId": "ci0-client-0",
    "defaultClientScopes": [
        "profile",
        "web-origins",
        "email",
        "roles",
    ],
    "description": "ci0-client-0-desc",
}


class Test_sort_data:
    @mark.parametrize(
        "data, expected_data",
        [
            ("myident", "myident"),
            (role_in_abc, role_out),
            (role_in_bac, role_out),
            (role_in_acb, role_out),
            (role_in_cba, role_out),
            # not needed
            # (role_in_attr_abc, role_out_attr),
            # (role_in_attr_bac, role_out_attr),
            # (role_in_attr_acb, role_out_attr),
            # (role_in_attr_cba, role_out_attr),
            #
            (apm_in_1, apm_out),
            (apm_in_2, apm_out),
            (dcs_in_1, dcs_out),
            (dcs_in_2, dcs_out),
        ]
    )
    def test_sort_data(self, data, expected_data):
        data_out = sort_json(data)
        # print('='*80)
        # print(f'data_out={json.dumps(data_out, indent=4)}')
        # print('='*80)
        assert expected_data == data_out

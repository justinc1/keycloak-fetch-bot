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
        ]
    )
    def test_normalize(self, identifier_in, expected_identifier):
        identifier_out = normalize(identifier_in)
        assert expected_identifier == identifier_out


role_in = {
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
            "name": "ci0-client0-role1b"
        },
        {
            "clientRole": True,
            "containerName": "ci0-client-0",
            "name": "ci0-client0-role1a"
        },
        {
            "clientRole": True,
            "containerName": "ci0-realm",
            "name": "ci0-role-1a"
        }
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
            "name": "ci0-client0-role1b"
        },
        {
            "clientRole": True,
            "containerName": "ci0-client-0",
            "name": "ci0-client0-role1a"
        },
        {
            "clientRole": True,
            "containerName": "ci0-realm",
            "name": "ci0-role-1a"
        }
    ],
    "description": "ci0-client0-role1-desc",
    "name": "ci0-client0-role1"
}
class Test_sort_data:
    @mark.parametrize(
        "data, expected_data",
        [
            ("myident", "myident"),
            (role_in, role_out),
        ]
    )
    def test_sort_data(self, data, expected_data):
        data_out = sort_json(data)
        assert expected_data == data_out


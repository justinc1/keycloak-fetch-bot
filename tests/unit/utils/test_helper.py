import json
import os
import shutil
from kcfetcher.utils.helper import remove_ids, normalize
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


class Test_normalize:
    @mark.parametrize(
        "identifier_in, expected_identifier",
        [
            ("myident", "myident"),
            ("aa/bb cc=dd,ee", "aa_bb_cc_dd_ee"),
            ("aa/bb cc=dd,ee---aa/bb cc=dd,ee", "aa_bb_cc_dd_ee---aa_bb_cc_dd_ee"),
        ]
    )
    def test_normalize(self, identifier_in, expected_identifier):
        identifier_out = normalize(identifier_in)
        assert expected_identifier == identifier_out

import json
import os
import shutil
from kcfetcher.utils.helper import remove_ids, normalize
# from tests.integration.test_ping import BaseTestClass
from pytest import mark


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

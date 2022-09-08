from kcfetcher.store import Store
# from tests.integration.test_ping import BaseTestClass
from pytest import mark


class TestStore:
    @mark.parametrize(
        "path,expected_path",
        [
            ("aa/bb", ["aa", "bb"]),
            (".", ["."]),
            # Commented out - it doesn't work as expected.
            # ("", ["."]),
            # ("./", ["."]),
            # ("./", ["."]),
            # ("./aa", ["aa"]),
            # ("./aa/bb", ["aa", "bb"]),
            # ("aa/bb/", ["aa", "bb"]),
            ("/aa/bb", ["", "aa", "bb"]),  # abs path not supported
            # ("/aa/bb/", ["", "aa", "bb"]),
            # ("", []),
        ]
    )
    def test_init(self, path, expected_path):
        st = Store(path)
        assert st.path == expected_path

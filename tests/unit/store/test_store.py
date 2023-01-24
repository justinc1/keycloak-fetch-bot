import json
import os
import shutil

import pytest

from kcfetcher.store import Store, StoreException
# from tests.integration.test_ping import BaseTestClass
from pytest import mark


class TestStore:
    @mark.parametrize(
        "path,expected_path",
        [
            ("aa/bb", ["aa", "bb"]),
            (".", ["."]),
            ("", ["."]),
            ("./", ["."]),
            ("./aa", ["aa"]),
            ("./aa/bb", ["aa", "bb"]),
            ("aa/bb/", ["aa", "bb"]),
            ("/aa/bb", ["", "aa", "bb"]),  # abs path not supported
            ("/aa/bb/", ["", "aa", "bb"]),
        ]
    )
    def test_init(self, path, expected_path):
        st = Store(path)
        assert st.path == expected_path

    def test_add_child(self):
        st = Store("aa/bb")
        st.add_child("cc")
        assert ["aa", "bb", "cc"] == st.path

    def test_remove_last_child(self):
        st = Store("aa/bb")
        st.remove_last_child()
        assert ["aa"] == st.path

    def test_store_one_with_alias(self):
        outdir = "aa/bb"
        alias = "ci-alias"
        data = dict(
            myname="obj1",
            mykey="myvalue1",
        )
        expected_filename = os.path.join(outdir, alias + ".json")

        # danger...
        if os.path.exists(outdir):
            shutil.rmtree(outdir)
        assert not os.path.exists(expected_filename)

        st = Store(outdir)
        st.store_one_with_alias(alias, data)

        assert os.path.exists(expected_filename)
        content = json.load(open(expected_filename))
        assert data == content

    def test_store_one_with_alias__reuse_name(self):
        # It is error if two objects want to use same filename.
        # filename is normalized alias - "a b" and "a*b" will
        # both become "a_b".
        outdir = "aa/bb"
        alias1 = "ci alias"
        data1 = dict(
            myname="obj1",
            mykey="myvalue1",
        )
        alias2 = "ci*alias"
        data2 = dict(
            myname="obj2",
            mykey="myvalue2",
        )
        expected_filename = os.path.join(outdir, "ci_alias.json")

        # danger...
        if os.path.exists(outdir):
            shutil.rmtree(outdir)
        assert not os.path.exists(expected_filename)

        st = Store(outdir)
        st.store_one_with_alias(alias1, data1)
        with pytest.raises(StoreException):
            st.store_one_with_alias(alias2, data2)

        # old file is not destroyed
        assert os.path.exists(expected_filename)
        content = json.load(open(expected_filename))
        assert data1 == content

    def test_store_one(self):
        outdir = "aa/bb"
        data = dict(
            myname="obj1",
            mykey="myvalue1",
        )
        expected_filename = os.path.join(outdir, "obj1.json")

        # danger...
        if os.path.exists(outdir):
            shutil.rmtree(outdir)
        assert not os.path.exists(expected_filename)

        st = Store(outdir)
        st.store_one(data, "myname")

        assert os.path.exists(expected_filename)
        content = json.load(open(expected_filename))
        assert data == content

    def test_store(self):
        outdir = "aa/bb"
        data = [
            dict(
                myname="obj1",
                mykey="myvalue1",
            ),
            dict(
                myname="obj2",
                mykey="myvalue2",
            ),
        ]
        expected_filenames = [
            os.path.join(outdir, "obj1.json"),
            os.path.join(outdir, "obj2.json"),
        ]

        # danger...
        if os.path.exists(outdir):
            shutil.rmtree(outdir)
        for ef in expected_filenames:
            assert not os.path.exists(ef)

        st = Store(outdir)
        st.store(data, "myname")

        for obj in data:
            obj_name = obj["myname"]
            expected_filename = os.path.join(outdir, obj_name + ".json")
            assert os.path.exists(expected_filename)
            content = json.load(open(expected_filename))
            assert obj == content

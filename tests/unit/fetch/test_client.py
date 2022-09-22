from pytest import mark
import json
import os
import shutil
from kcfetcher.fetch import ClientFetch


class MockupStoreApi:
    def add_child(self, child_name):
        pass

    def store_one(self, data, identifier):
        pass

    def store_one_with_alias(self, alias, data):
        pass

    def remove_last_child(self):
        pass


class MockupKc:
    def build(self, name, realm):
        return MockupClients()


class MockupClients:
    def roles(self, query):
        return {}

    def all(self):
        return []


# manually written mockup classes
class TestClientFetch:
    def test_fetch(self):
        store_api = MockupStoreApi()
        kc = MockupKc()
        resource_name = "ci-resource"

        obj = ClientFetch(kc, resource_name)
        obj.id = "ci-id"
        obj.realm = "ci-realm"

        obj.fetch(store_api)

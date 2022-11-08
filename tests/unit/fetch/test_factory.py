from pytest import mark
import json
import os
import shutil
from kcfetcher.fetch import FetchFactory, CustomAuthenticationFetch, ClientFetch, ComponentFetch, GenericFetch


class TestFactory:
    @mark.parametrize(
        "resource_name, resource_id, expected_fetch_class",
        [
            ("roles", "name", GenericFetch),
            ("components", "name", ComponentFetch),
            ("authentication", "alias", CustomAuthenticationFetch),
            ("clients", "clientId", ClientFetch),
            ("random-mock-resource-name", "name", GenericFetch),
        ]
    )
    def test_create(self, resource_name, resource_id, expected_fetch_class):
        resource = [resource_name, resource_id]
        factory = FetchFactory()
        client = factory.create(resource, "mock-kc", "mock-realm")
        assert isinstance(client, expected_fetch_class)

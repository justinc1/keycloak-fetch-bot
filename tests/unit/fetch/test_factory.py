from pytest import mark
import json
import os
import shutil
from kcfetcher.fetch import FetchFactory, CustomAuthenticationFetch, ClientFetch, GenericFetch


class TestFactory:
    @mark.parametrize(
        "resource_name, expected_fetch_class",
        [
            ("components", GenericFetch),
            ("authentication", CustomAuthenticationFetch),
            ("clients", ClientFetch),
            ("random-mock-resource-name", GenericFetch),
        ]
    )
    def test_create(self, resource_name, expected_fetch_class):
        resource = [resource_name, "mock-resource-id"]
        factory = FetchFactory()
        client = factory.create(resource, "mock-kc", "mock-realm")
        assert isinstance(client, expected_fetch_class)

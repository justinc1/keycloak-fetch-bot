from kcfetcher.fetch import GenericFetch


class ClientRegistrationPolicyFetch(GenericFetch):
    # REST APi query filter
    api_object_type = "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"

    def __init__(self, kc, resource_name, resource_id="", realm=""):
        super().__init__(kc, resource_name, resource_id, realm)
        assert "client-registration-policies" == self.resource_name
        assert "name" == self.id

    def fetch(self, store_api):
        name = self.resource_name
        identifier = self.id

        print('** Client registration policies fetching: ', name)

        kc_objects = self._get_data()
        object_subtypes = [
            "anonymous",
            "authenticated",
        ]
        for subtype in object_subtypes:
            store_api.add_child(subtype)  # client-registration-policies/authenticated
            for kc_object in kc_objects:
                assert kc_object["subType"] in object_subtypes
                if kc_object["subType"] != subtype:
                    continue
                store_api.store_one(kc_object, identifier)
            store_api.remove_last_child()  # client-registration-policies/authenticated

    def all(self, kc):
        kc = self.kc.build("components", self.realm)
        query_params = dict(type=self.api_object_type)
        all_components = kc.all(params=query_params)
        realm_id = self.kc.admin().get(self.realm).verify().resp().json()["id"]
        for obj in all_components:
            assert obj["parentId"] == realm_id
        # TODO blacklist if needed
        return all_components

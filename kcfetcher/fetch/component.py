from kcfetcher.fetch import UserFederationFetch
from kcfetcher.fetch import GenericFetch

"""
Whole component fetch is temporal thing.
Likely every component type should be moved to a dedicated class,
until nothing is left for ComponentFetch.

Most components (at least those that are part of realm by default) have "name" attribute.
But some don't have it, example:
    {'id': '81c8c815-0d3a-480f-a6ee-3c6f7324a8cb', 'providerId': 'declarative-user-profile', 'providerType': 'org.keycloak.userprofile.UserProfileProvider', 'parentId': 'ci0-realm', 'config': {}}

The missing "name" would usually by typo, we want to ignore this only in very specific cases.
"""

import logging
logger = logging.getLogger(__name__)


class ComponentFetch(GenericFetch):
    def __init__(self, kc, resource_name, resource_id="", realm=""):
        super().__init__(kc, resource_name, resource_id, realm)
        assert "components" == self.resource_name
        assert "name" == self.id

    def all(self, kc):
        objects = kc.all()
        realm_id = self.kc.admin().get(self.realm).verify().resp().json()["id"]
        forbidden_provider_types = ["org.keycloak.userprofile.UserProfileProvider"]
        objects2 = []
        user_federation_fetch = UserFederationFetch(self.kc, "user-federations", "name", self.realm)
        all_user_federations = user_federation_fetch.all_from_components(objects)
        all_user_federation_ids = [uf["id"] for uf in all_user_federations]
        all_uf_all_mappers = user_federation_fetch.get_all_mappers(objects, all_user_federation_ids)
        all_uf_all_mappers_ids = [ufm["id"] for ufm in all_uf_all_mappers]

        for obj in objects:
            if "providerType" in obj and obj["providerType"] in forbidden_provider_types:
                # This one has no name, so do not check the name
                # We just drop it for now
                assert 'name' not in obj
                logger.warning(f"Component {obj} was not saved, it has no name.")
                continue

            # do not store components that are included somewhere else
            if obj["id"] in all_user_federation_ids:
                # saved by UserFederationFetch
                assert obj["providerType"] == "org.keycloak.storage.UserStorageProvider"
                assert obj["parentId"] == realm_id
                continue

            if obj["id"] in all_uf_all_mappers_ids:
                # saved by UserFederationFetch - mappers
                # Interesting and suspicious: keycloak/ci0-realm/user-federations/ci0-uf0-ldap/mappers/email.json -
                # it was never saved under components/ subdirectory.
                # TODO: check if all other mappers are shared by all user federations.
                assert obj["providerType"] == "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
                assert obj["parentId"] in all_user_federation_ids
                continue

            if obj[self.id] in self.black_list:
                continue
            objects2.append(obj)
        return objects2

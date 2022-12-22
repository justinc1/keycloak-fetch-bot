import logging
import sys
from kcfetcher.fetch import GenericFetch
from kcfetcher.utils import normalize

logger = logging.getLogger(__name__)


class IdentityProviderFetch(GenericFetch):
    def fetch(self, store_api):
        name = self.resource_name
        identifier = self.id

        print('** Identity Provider fetching: ', name)

        kc_objects = self._get_data()
        # https://172.17.0.2:8443/auth/admin/realms/ci0-realm/identity-provider/instances
        idp_api = self.kc.build(self.resource_name, self.realm)
        counter = 0
        for kc_object in kc_objects:
            store_api.add_child(normalize(kc_object[identifier]))  # identity-provider/<idp_alias>
            store_api.store_one(kc_object, identifier)

            # For each identity provider, store also mappers
            idp_alias = kc_object["alias"]
            # https://172.17.0.2:8443/auth/admin/realms/ci0-realm/identity-provider/instances/ci0-idp-saml-0/mappers
            idp_mappers_api = idp_api.get_child(idp_api, idp_alias, "mappers")
            mappers = idp_mappers_api.all()
            # remove parentId - it is a UUID
            for mapper in mappers:
                mapper.pop("id")

            store_api.add_child('mappers')
            store_api.store(mappers, "name")
            store_api.remove_last_child()  # identity-provider/<idp_alias>/mappers
            store_api.remove_last_child()  # identity-provider/<idp_alias>
            counter += 1

    def _get_data(self):
        kc = self.kc.build(self.resource_name, self.realm)
        kc_objects = self.all(kc)

        for kc_object in kc_objects:
            # remove internalId
            kc_object.pop("internalId")

            # Show error if provider type is not SAML.
            # Also openid v1 seems to work, but we didn't check all attributes.
            tested_provider_ids = ["saml"]
            if kc_object['providerId'] not in tested_provider_ids:
                logger.error(f"Identity provider providerId={kc_object['providerId']} is not sufficiently tested, realm={self.realm} alias={kc_object['alias']}")
                sys.exit(1)

        return kc_objects

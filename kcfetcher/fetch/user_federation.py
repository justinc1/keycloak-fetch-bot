from copy import copy
from kcfetcher.fetch import GenericFetch
from kcfetcher.utils import normalize, find_in_list


class UserFederationFetch(GenericFetch):
    def __init__(self, kc, resource_name, resource_id="", realm=""):
        super().__init__(kc, resource_name, resource_id, realm)
        assert "user-federations" == self.resource_name
        assert "name" == self.id

    def fetch(self, store_api):
        name = self.resource_name
        identifier = self.id

        print('** User federation fetching: ', name)

        kc_objects = self._get_data()
        components_api = self.kc.build("components", self.realm)
        all_components = components_api.all()
        counter = 0
        for kc_object in kc_objects:
            store_api.add_child(normalize(kc_object[identifier]))  # user-federations/federation_name
            store_api.store_one(kc_object, identifier)

            # For each user federation, store also mappers
            user_federation_id = kc_object["id"]
            mappers = self.get_all_mappers(all_components, [user_federation_id])
            # remove parentId - it is a UUID
            for mapper in mappers:
                mapper.pop("parentId")

            store_api.add_child('mappers')
            store_api.store(mappers, "name")
            store_api.remove_last_child()  # user-federations/federation_name
            store_api.remove_last_child()  # user-federations/federation_name/mappers
            counter += 1

    def _get_data(self):
        kc = self.kc.build("components", self.realm)
        kc_objects = self.all(kc)

        master_realm_api = self.kc.admin()
        realms = master_realm_api.all()
        for obj in kc_objects:
            # replace realm id with realm name
            realm_id = obj.pop("parentId")
            realm = find_in_list(realms, id=realm_id)
            realm_name = realm["realm"]
            obj["parentName"] = realm_name
            if obj["providerId"] == "ldap":
                # remove LDAP bindCredential from config - it is all '********' anyway
                obj["config"].pop("bindCredential")

        return kc_objects

    def all_from_components(self, components):
        assert isinstance(components, list)
        # parentId must be our realm_name
        realm_id = self.kc.admin().get(self.realm).verify().resp().json()["id"]
        all_user_federations = [
            obj for obj in components if (
                obj["providerType"] == "org.keycloak.storage.UserStorageProvider" and
                obj["parentId"] == realm_id
        )]
        # There is no default user federation, so nothing is blacklisted.
        # all_user_federations = list(filter(lambda fn: not fn[self.id] in self.black_list, all_user_federations))
        return all_user_federations

    def all(self, kc):
        # Sample URL used by GUI:
        # https://172.17.0.2:8443/auth/admin/realms/ci0-realm/components?parent=ci0-realm&type=org.keycloak.storage.UserStorageProvider
        # kcapi does not accept query params, so we get all components, and filter them here.
        all_components = kc.all()
        return self.all_from_components(all_components)

    def get_all_mappers(self, components, user_federation_ids):
        # Get from all components only those mappers that belong to specified user federations
        assert isinstance(user_federation_ids, list)
        mappers = [
            copy(obj) for obj in components if (
                obj["providerType"] == "org.keycloak.storage.ldap.mappers.LDAPStorageMapper" and
                obj["parentId"] in user_federation_ids
            )]
        return mappers

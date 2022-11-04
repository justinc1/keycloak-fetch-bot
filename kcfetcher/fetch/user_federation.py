from kcfetcher.fetch import GenericFetch


class UserFederationFetch(GenericFetch):
    def __init__(self, kc, resource_name, resource_id="", realm=""):
        super().__init__(kc, resource_name, resource_id, realm)
        assert "user-federations" == self.resource_name
        assert "name" == self.id

    def _get_data(self):
        kc = self.kc.build("components", self.realm)
        kc_objects = self.all(kc)
        return kc_objects

    def all(self, kc):
        # Sample URL used by GUI:
        # https://172.17.0.2:8443/auth/admin/realms/ci0-realm/components?parent=ci0-realm&type=org.keycloak.storage.UserStorageProvider
        # kcapi does not accept query params, so we get all components, and filter them here.
        all_components = kc.all()
        # parentId must be our realm_name
        all_user_federations = [
            obj for obj in all_components if (
                obj["providerType"] == "org.keycloak.storage.UserStorageProvider" and
                obj["parentId"] == self.realm
        )]
        # There is no default user federation, so nothing is blacklisted.
        # all_user_federations = list(filter(lambda fn: not fn[self.id] in self.black_list, all_user_federations))
        return all_user_federations

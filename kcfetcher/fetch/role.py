import logging
from kcfetcher.fetch import GenericFetch

logger = logging.getLogger(__name__)


# A realm role
class RoleFetch(GenericFetch):
    def __init__(self, kc, resource_name, resource_id="", realm=""):
        super().__init__(kc, resource_name, resource_id, realm)
        assert "roles" == self.resource_name
        assert "name" == self.id

    def _get_data(self):
        roles_api = self.kc.build(self.resource_name, self.realm)
        brief_roles = self.all(roles_api)
        # But we used GET /{realm}/roles - it missed .attributes attribute (it is briefRepresentation).
        # We get full role representation from GET /{realm}/roles-by-id/{role-id}
        roles_by_id_api = self.kc.build("roles-by-id", self.realm)
        roles = []
        for brief_role in brief_roles:
            role = roles_by_id_api.get(brief_role["id"]).verify().resp().json()
            roles.append(role)

        return roles

    def all(self, kc):
        return list(filter(lambda fn: not fn[self.id] in self.black_list, kc.all()))

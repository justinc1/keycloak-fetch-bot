import logging

from kcfetcher.utils import minimize_role_representation
from kcfetcher.fetch import GenericFetch

logger = logging.getLogger(__name__)


# A realm role
class RoleFetch(GenericFetch):
    def __init__(self, kc, resource_name, resource_id="", realm=""):
        super().__init__(kc, resource_name, resource_id, realm)
        assert "name" == self.id

        # assert self.resource_name in ["roles", "clients/1e0807cf-7aa1-4ddf-8aa0-7d117d476785/roles"]
        if self.resource_name == "roles":
            # fetching realm roles
            pass
        else:
            # fetching client roles, client by client
            assert len(self.resource_name) == 50
            assert len(self.resource_name.split("/")) == 3
            assert self.resource_name.split("/")[0] == "clients"
            assert self.resource_name.split("/")[2] == "roles"

    def _get_data(self):
        roles_api = self.kc.build(self.resource_name, self.realm)
        brief_roles = self.all(roles_api)
        # But we used GET /{realm}/roles - it missed .attributes attribute (it is briefRepresentation).
        # We get full role representation from GET /{realm}/roles-by-id/{role-id}
        roles_by_id_api = self.kc.build("roles-by-id", self.realm)
        clients_api = self.kc.build("clients", self.realm)
        clients = self.all(clients_api)
        roles = []
        for brief_role in brief_roles:
            role_id = brief_role["id"]
            role = roles_by_id_api.get(role_id).verify().resp().json()

            # the containerId needs to be removed, it is UUID (clientID for client roles, realm name for realm roles)
            if role['clientRole']:
                # must be parent client UUID, check the length
                assert len(role["containerId"]) == 36
            else:
                assert role["containerId"] == self.realm
            role.pop("containerId")

            if role["composite"]:
                # Now add composites into role dict
                # For client role, we need to replace containerId (UUID) with client.clientId (string)
                assert "composites" not in role
                composites = roles_by_id_api.get(f"{role_id}/composites").verify().resp().json()
                role["composites"] = [minimize_role_representation(cc, clients) for cc in composites]

            roles.append(role)

        return roles

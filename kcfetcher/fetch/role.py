import itertools
import logging
from copy import copy

from kcfetcher.utils import minimize_role_representation
from kcfetcher.fetch import GenericFetch

logger = logging.getLogger(__name__)

"""
RH SOSO 7.4:
Client roles do not have "default roles" concept.
Realm roles have default roles concept.
When fetching realm roles, default-roles are not included into dedicated .json file.
The default roles are part of realm.json and 0-N client.json files.
For example, in master realm, add create-client role from both "master-realm" and "ci0-realm-realm" realms,
and they will be saved to:
  "master/clients/client-1/master-realm.json"
  "master/clients/client-0/ci0-realm-realm.json"

if self.kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_4: no code needed
"""

def role_sort_composites(data):
    assert isinstance(data, list)
    assert isinstance(data[0], dict)
    assert "name" in data[0]
    assert "containerName" in data[0]
    data = sorted(data, key=lambda obj: (obj["name"], obj["containerName"]))
    return data


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
        # We used GET /{realm}/roles - response misses .attributes attribute (it is briefRepresentation).
        # We get full role representation from GET /{realm}/roles-by-id/{role-id}
        roles_by_id_api = self.kc.build("roles-by-id", self.realm)
        clients_api = self.kc.build("clients", self.realm)
        realms = self.kc.admin().all()
        realm_ids = [rr["id"] for rr in realms]
        clients = clients_api.all()
        roles = []
        for brief_role in brief_roles:
            role_id = brief_role["id"]
            role = roles_by_id_api.get(role_id).verify().resp().json()

            # the containerId needs to be removed, it is UUID (clientID for client roles, realm name for realm roles)
            if role['clientRole']:
                # must be parent client UUID, check the length
                assert len(role["containerId"]) == 36
            else:
                assert role["containerId"] in realm_ids
            role.pop("containerId")

            if role["composite"]:
                # Now add composites into role dict
                # For client role, we need to replace containerId (UUID) with client.clientId (string)
                assert "composites" not in role
                composites = roles_by_id_api.get(f"{role_id}/composites").verify().resp().json()
                role["composites"] = [minimize_role_representation(cc, realms, clients) for cc in composites]

                # master realm, roles/admin.json - composites will contain "manage-authorization" role from multiple clients.
                # sort list, first by name, then by containerName
                role["composites"] = role_sort_composites(role["composites"])

            roles.append(role)

        return roles

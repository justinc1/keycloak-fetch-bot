from kcapi.rest.crud import KeycloakCRUD

from kcfetcher.fetch import GenericFetch
from kcfetcher.utils import find_in_list

class ClientFetch(GenericFetch):
    def fetch(self, store_api):
        assert "clients" == self.resource_name
        assert "clientId" == self.id

        name = self.resource_name
        identifier = self.id
        realm = self.realm

        clients_api = self.kc.build(name, realm)

        print('** Client fetching: ', name)
        kc_objects = self.all(clients_api)

        counter = 0
        for kc_object in kc_objects:
            store_api.add_child('client-' + str(counter))  # clients/<client_ind>
            store_api.store_one(kc_object, identifier)

            client_query = {'key': 'clientId', 'value': kc_object['clientId']}
            # GET /{realm}/clients/{id}/roles - briefRepresentation=True is default
            # We get full RoleRepresentation from
            #   GET /{realm}/clients/{id}/roles/{role-name} or
            #   GET /{realm}/roles-by-id/{role-id}
            # RoleRepresentation includes .attributes attribute.
            roles_brief = clients_api.roles(client_query).all()
            roles_by_id_api = self.kc.build("roles-by-id", realm)
            roles = [
                roles_by_id_api.get(role_brief['id']).verify().resp().json()
                for role_brief in roles_brief
            ]
            # But composites are missing :/.
            # Get them from GET /{realm}/clients/{id}/roles/{role-name}/composites.
            client_id = kc_object['id']
            client_roles_api = self.kc.build(f"clients/{client_id}/roles", realm)
            for role in roles:
                # the containerId needs to be removed, it is client clientID (UUID)
                assert role["containerId"] == client_id
                role.pop("containerId")

                if not role["composite"]:
                    continue
                composites = client_roles_api.get(f"{role['name']}/composites").verify().resp().json()

                if 0:
                    # Those two are same. Are they nicer the code above?
                    client_role_composites_api = clients_api.roles(client_query).get_child(clients_api, f"{client_id}/roles/{role['name']}", "composites")
                    client_role_composites_api = KeycloakCRUD.get_child(clients_api, f"{client_id}/roles/{role['name']}", "composites")
                    x = client_role_composites_api.get(_id=None).verify().resp().json()

                # Now add composites into role dict
                # For client role, we need to replace containerId (UUID) with client.clientId (string)
                # For realm role, containerId is realm name.
                # Each composite in only a "pointer" to a role, remove irrelevant attributes.
                composites_minimal = []
                for composite in composites:
                    containerId = composite["containerId"]
                    container_name = containerId
                    if composite["clientRole"]:
                        container_name = find_in_list(kc_objects, id=containerId)["clientId"]
                    composite_minimal = dict(
                        name=composite["name"],
                        clientRole=composite["clientRole"],
                        containerName=container_name,
                    )
                    composites_minimal.append(composite_minimal)
                assert "composites" not in role
                role["composites"] = composites_minimal

            store_api.add_child('roles')  # clients/<client_ind>/roles
            store_api.store_one_with_alias('roles', roles)

            store_api.remove_last_child()  # clients/<client_ind>/roles
            store_api.remove_last_child()  # clients/<client_ind>
            counter += 1

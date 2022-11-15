from kcapi.rest.crud import KeycloakCRUD

from kcfetcher.fetch import GenericFetch
from kcfetcher.utils import find_in_list, minimize_role_representation


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

        auth_flow_api = self.kc.build("authentication", realm)
        auth_flow_all = auth_flow_api.all()

        counter = 0
        client_id_all = [client["id"] for client in kc_objects]
        for kc_object in kc_objects:
            store_api.add_child('client-' + str(counter))  # clients/<client_ind>
            # authenticationFlowBindingOverrides need to be saved with auth flow alias/name, not id/UUID
            for auth_flow_override in kc_object["authenticationFlowBindingOverrides"]:
                auth_flow_id = kc_object["authenticationFlowBindingOverrides"][auth_flow_override]
                auth_flow_alias = find_in_list(auth_flow_all, id=auth_flow_id)["alias"]
                kc_object["authenticationFlowBindingOverrides"][auth_flow_override] = auth_flow_alias
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
                assert "composites" not in role
                role["composites"] = [minimize_role_representation(cc, kc_objects) for cc in composites]

            store_api.add_child('roles')  # clients/<client_ind>/roles
            store_api.store_one_with_alias('roles', roles)
            store_api.remove_last_child()  # clients/<client_ind>/roles

            # Compute scope-mappings
            client_scope_mappings_api = self.kc.build(f"clients/{client_id}/scope-mappings", realm)
            client_scope_mappings_all = client_scope_mappings_api.get("realm").verify().resp().json()
            # now add scope_mappings for each client
            # TODO FIXME client_id_all should include client['id'] of blacklisted client too (all default clients are blacklisted) !!!!
            for cid in client_id_all:
                client_scope_mappings_all += client_scope_mappings_api.get(f"clients/{cid}").verify().resp().json()
            # Similar to client/realm roles, only a minimal representation is saved.
            client_scope_mappings_all_minimal = [minimize_role_representation(sc, kc_objects) for sc in client_scope_mappings_all]
            store_api.store_one_with_alias('scope-mappings', client_scope_mappings_all_minimal)

            store_api.remove_last_child()  # clients/<client_ind>
            counter += 1

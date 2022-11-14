from kcfetcher.fetch import GenericFetch


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

            client_roles_query = {'key': 'clientId', 'value': kc_object['clientId']}
            # GET /{realm}/clients/{id}/roles - briefRepresentation=True is default
            # We get full RoleRepresentation from
            #   GET /{realm}/clients/{id}/roles/{role-name} or
            #   GET /{realm}/roles-by-id/{role-id}
            roles_brief = clients_api.roles(client_roles_query).all()
            roles_by_id_api = self.kc.build("roles-by-id", realm)
            roles = [
                roles_by_id_api.get(role_brief['id']).verify().resp().json()
                for role_brief in roles_brief
            ]

            store_api.add_child('roles')  # clients/<client_ind>/roles
            store_api.store_one_with_alias('roles', roles)

            store_api.remove_last_child()  # clients/<client_ind>/roles
            store_api.remove_last_child()  # clients/<client_ind>
            counter += 1

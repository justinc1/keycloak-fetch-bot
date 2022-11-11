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
            store_api.add_child('client-' + str(counter))  # auth/authentication_name
            store_api.store_one(kc_object, identifier)

            client_roles_query = {'key': 'clientId', 'value': kc_object['clientId']}
            roles = clients_api.roles(client_roles_query).all()
            store_api.add_child('roles')  # auth/authentication_name/executions
            store_api.store_one_with_alias('roles', roles)

            store_api.remove_last_child()  # clients/<clients>/*executions*
            store_api.remove_last_child()  # clients/*clients*
            counter += 1

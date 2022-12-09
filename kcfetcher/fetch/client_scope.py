from kcfetcher.fetch import GenericFetch


class ClientScopeFetch(GenericFetch):
    def __init__(self, kc, resource_name, resource_id="", realm=""):
        super().__init__(kc, resource_name, resource_id, realm)
        assert "client-scopes" == self.resource_name
        assert "name" == self.id

    def _get_data(self):
        kc = self.kc.build(self.resource_name, self.realm)
        kc_objects = self.all(kc)
        # for each client-scope, get also assigned realm (and maybe client) roles
        # realm roles
        for client_scope in kc_objects:
            # get realm roles
            # GET /{realm}/client-scopes/{id}/scope-mappings/realm
            client_scope_id = client_scope["id"]
            client_scope_scope_mappings_realm = self.kc.build(f"client-scopes/{client_scope_id}/scope-mappings/realm", self.realm)
            roles = client_scope_scope_mappings_realm.all()
            realm_roles_names = [role["name"] for role in roles]
            # scopeMappings stores mapping to realm roles
            scope_mappings = {
                "scopeMappings": {
                    "roles": realm_roles_names
                }
            }
            client_scope.update(scope_mappings)

            # get client roles
            # GET /{realm}/client-scopes/{id}/scope-mappings/clients/{client}
            kc_clients = self.kc.build("clients", self.realm)
            clients = kc_clients.all()
            all_clients_roles_names = {}
            for client in clients:
                client_id = client["id"]
                client_scope_scope_mappings_clients = self.kc.build(f"client-scopes/{client_scope_id}/scope-mappings/clients/{client_id}", self.realm)
                roles = client_scope_scope_mappings_clients.all()
                client_roles_names = [role["name"] for role in roles]
                print(f"client={client['clientId']} client_roles_names={client_roles_names}")
                if client_roles_names:
                    all_clients_roles_names.update({client['clientId']: client_roles_names})
            # clientScopeMappings stores mapping to client roles
            client_scope_mappings = {
                "clientScopeMappings": all_clients_roles_names,
            }
            client_scope.update(client_scope_mappings)

        return kc_objects

    def fetch(self, store_api):
        super().fetch(store_api)
        default_client_scope_fetchers = [
            DefaultClientScopeFetch(self.kc, "default-default-client-scopes", "name", self.realm),
            DefaultClientScopeFetch(self.kc, "default-optional-client-scopes", "name", self.realm),
        ]
        store_api.add_child('default')  # client-scopes/default
        for default_client_scope_fetcher in default_client_scope_fetchers:
            default_client_scope_fetcher.fetch(store_api)
        store_api.remove_last_child()  # client-scopes/default


class DefaultClientScopeFetch(GenericFetch):
    """
    Fetch default-default-client-scopes or default-optional-client-scopes
    """
    def __init__(self, kc, resource_name, resource_id="", realm=""):
        super().__init__(kc, resource_name, resource_id, realm)
        assert self.resource_name in [
            "default-default-client-scopes",
            "default-optional-client-scopes",
        ]
        # NOTE - here name as ID is useless. We store only complete list.
        # Individual elementes are stored by ClientScopeFetch.
        assert "name" == self.id

    def all(self, kc):
        # Do not remove default client-scope objects.
        # We need them, user can assign/remove them to/from defautl-x-client-scopes.
        all_objects = kc.all()
        return all_objects

    def _get_data(self):
        kc = self.kc.build(self.resource_name, self.realm)
        kc_objects = self.all(kc)
        # Response is list of dict, attributes .name and .id
        # In json we want to store only client_scope name.
        data = [obj["name"] for obj in kc_objects]
        data = sorted(data)
        return data

    def fetch(self, store_api):
        name = self.resource_name
        identifier = self.id

        print('--> fetching: ', name)

        data = self._get_data()

        # store_api.store(kc_objects, identifier)
        store_api.store_one_with_alias(self.resource_name, data)

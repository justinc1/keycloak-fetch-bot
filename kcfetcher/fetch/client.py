from kcapi.rest.crud import KeycloakCRUD

from kcfetcher.fetch import GenericFetch
from kcfetcher.fetch.role import RoleFetch
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
        realms = self.kc.admin().all()

        counter = 0
        client_id_all = [client["id"] for client in kc_objects]
        for kc_object in kc_objects:
            client_id = kc_object['id']
            store_api.add_child('client-' + str(counter))  # clients/<client_ind>
            # authenticationFlowBindingOverrides need to be saved with auth flow alias/name, not id/UUID
            for auth_flow_override in kc_object["authenticationFlowBindingOverrides"]:
                auth_flow_id = kc_object["authenticationFlowBindingOverrides"][auth_flow_override]
                auth_flow_alias = find_in_list(auth_flow_all, id=auth_flow_id)["alias"]
                kc_object["authenticationFlowBindingOverrides"][auth_flow_override] = auth_flow_alias
            # SAML client - do not store 'saml.signing.certificate' and 'saml.signing.private.key'
            kc_object["attributes"].pop('saml.signing.certificate', None)
            kc_object["attributes"].pop('saml.signing.private.key', None)

            # SAML or OIDC client - defaultClientScopes and optionalClientScopes are now in dedicated file
            # What KC 9.0 API returns wrong data for /clients/{client_id} endpoint,
            # attributes defaultClientScopes and optionalClientScope.
            # Correct data is returned by /clients/{client_id}/default-client-scopes.
            # Also those defaultClientScopes and optionalClientScope are ingored on PUT to /clients/{id}.
            kc_object.pop('defaultClientScopes')
            kc_object.pop('optionalClientScopes')

            store_api.store_one(kc_object, identifier)

            role_fetcher = RoleFetch(self.kc, f"clients/{client_id}/roles", "name", self.realm)
            store_api.add_child('roles')  # clients/<client_ind>/roles
            role_fetcher.fetch(store_api)
            store_api.remove_last_child()  # clients/<client_ind>/roles

            # Compute scope-mappings
            client_scope_mappings_api = self.kc.build(f"clients/{client_id}/scope-mappings", realm)
            client_scope_mappings_all = client_scope_mappings_api.get("realm").verify().resp().json()
            # now add scope_mappings for each client
            # TODO FIXME client_id_all should include client['id'] of blacklisted client too (all default clients are blacklisted) !!!!
            for cid in client_id_all:
                client_scope_mappings_all += client_scope_mappings_api.get(f"clients/{cid}").verify().resp().json()
            # Similar to client/realm roles, only a minimal representation is saved.
            client_scope_mappings_all_minimal = [minimize_role_representation(sc, realms, kc_objects) for sc in client_scope_mappings_all]
            store_api.store_one_with_alias('scope-mappings', client_scope_mappings_all_minimal)

            store_api.add_child('client-scopes')  # clients/<client_ind>/client-scopes
            cdcf = ClientDefaultClientScopeFetch(self.kc, self.realm, client_id=client_id)
            cdcf.fetch(store_api)
            cocf = ClientOptionalClientScopeFetch(self.kc, self.realm, client_id=client_id)
            cocf.fetch(store_api)
            store_api.remove_last_child()  # clients/<client_ind>/client-scopes

            store_api.remove_last_child()  # clients/<client_ind>
            counter += 1


class ClientClientScopeFetchBase(GenericFetch):
    # GET https://172.17.0.2:8443/auth/admin/realms/ci0-realm/clients/{client_id}/default-client-scopes
    # GET https://172.17.0.2:8443/auth/admin/realms/ci0-realm/clients/{client_id}/optional-client-scopes
    # _resource_name_template = 'clients/{client_id}/default-client-scopes'
    # _filename = "default-client-scopes"

    def __init__(self, kc, realm, *, client_id: str):
        resource_name = self._resource_name_template.format(client_id=client_id)
        resource_id = "name"
        super().__init__(kc, resource_name, resource_id, realm)
        self._client_id = client_id
        # Here we do not want to forget default client-scopes that are assigned.
        self.black_list = []

    def fetch(self, store_api):
        print('** Client client-scope fetching: ', self.resource_name)
        assigned_client_scopes = self._get_data()
        # we store only client-scope names
        assigned_client_scopes_minimal = [cs["name"] for cs in assigned_client_scopes]
        assigned_client_scopes_minimal = sorted(assigned_client_scopes_minimal)
        store_api.store_one_with_alias(self._filename, assigned_client_scopes_minimal)


class ClientDefaultClientScopeFetch(ClientClientScopeFetchBase):
    _resource_name_template = 'clients/{client_id}/default-client-scopes'
    _filename = "default-client-scopes"


class ClientOptionalClientScopeFetch(ClientClientScopeFetchBase):
    _resource_name_template = 'clients/{client_id}/optional-client-scopes'
    _filename = "optional-client-scopes"

from kcfetcher.fetch import CustomAuthenticationFetch, ClientFetch, GenericFetch, UserFetch, ClientScopeFetch,\
    UserFederationFetch, ComponentFetch, IdentityProviderFetch, RoleFetch


class FetchFactory:
    def __init__(self):
        self.strategies = {
            'authentication': CustomAuthenticationFetch,
            'clients': ClientFetch,
            'client-scopes': ClientScopeFetch,
            'users': UserFetch,
            'user-federations': UserFederationFetch,
            'identity-provider': IdentityProviderFetch,
            'roles': RoleFetch,
            'components': ComponentFetch,
        }

    def create(self, resource, kc, realm):
        resource_name = resource[0]
        resource_id = resource[1]

        if resource_name in self.strategies:
            return self.strategies[resource_name](kc, resource_name, resource_id, realm)

        return GenericFetch(kc, resource_name, resource_id, realm)

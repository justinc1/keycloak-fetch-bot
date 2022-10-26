from kcfetcher.fetch import GenericFetch


class ClientScopeFetch(GenericFetch):
    def __init__(self, kc, resource_name, resource_id="", realm=""):
        super().__init__(kc, resource_name, resource_id, realm)
        assert "client-scopes" == self.resource_name
        assert "name" == self.id

    def _get_data(self):
        kc = self.kc.build(self.resource_name, self.realm)
        kc_objects = self.all(kc)
        return kc_objects

    # def all(self, kc):
    #     return list(filter(lambda fn: not fn[self.id] in self.black_list, kc.all()))

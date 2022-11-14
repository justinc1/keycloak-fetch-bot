from kcfetcher.fetch import GenericFetch


class IdentityProviderFetch(GenericFetch):
    def _get_data(self):
        kc = self.kc.build(self.resource_name, self.realm)
        kc_objects = self.all(kc)
        # remove internalId
        for kc_object in kc_objects:
            kc_object.pop("internalId")
        return kc_objects

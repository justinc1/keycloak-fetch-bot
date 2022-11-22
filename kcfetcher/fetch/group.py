from kcfetcher.fetch import GenericFetch


class GroupFetch(GenericFetch):
    def _get_data(self):

        groups_api = self.kc.build(self.resource_name, self.realm)  # briefRepresentation=true
        kc_objects_brief = self.all(groups_api)
        kc_objects2 = []
        for obj_brief in kc_objects_brief:
            obj = groups_api.get(obj_brief["id"]).verify().resp().json()
            kc_objects2.append(obj)
        return kc_objects2

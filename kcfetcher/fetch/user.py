from kcfetcher.fetch import GenericFetch


class UserFetch(GenericFetch):
    def _get_data(self):
        # Each user is a leaf object in tree.
        # We only need to add attributes not returned by self.all().
        kc = self.kc.build(self.resource_name, self.realm)
        kc_objects = self.all(kc)
        kc_objects2 = []
        for obj in kc_objects:
            groups = kc.groups({"key": "username", "value": obj["username"]})
            obj.update({
                "groups": [gg["name"] for gg in groups],
            })
            kc_objects2.append(obj)
        # TODO roles assigned to user are missing. Add them if this is needed.
        return kc_objects2

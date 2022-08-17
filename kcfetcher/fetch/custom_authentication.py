from kcfetcher.fetch import GenericFetch


class CustomAuthenticationFetch(GenericFetch):
    def normalize(self, identifier=""):
        return identifier.lower().replace('//', '_').replace(' ', '_')

    def fetch(self, store_api):
        name = self.resource_name
        identifier = self.id
        realm = self.realm

        authentication_api = self.kc.build(name, realm)

        print('** Authentication fetching: ', name)

        kc_objects = self.all(authentication_api)

        counter = 0
        for kc_object in kc_objects:
            store_api.add_child(self.normalize(kc_object[identifier]))  # auth/authentication_name
            store_api.store_one(kc_object, identifier)

            executors = authentication_api.executions(kc_object).all()
            store_api.add_child('executors')  # auth/authentication_name/executions
            store_api.store_one_with_alias('executors', executors)

            store_api.remove_last_child()  # auth/auth_name/*executions*
            store_api.remove_last_child()  # auth/*authentication_name*
            counter += 1
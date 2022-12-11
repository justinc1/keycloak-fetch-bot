from kcfetcher.fetch import GenericFetch
from kcfetcher.utils import normalize


class CustomAuthenticationFetch(GenericFetch):
    # This class stores authentication flows.
    def fetch(self, store_api):
        name = self.resource_name
        identifier = self.id
        realm = self.realm

        authentication_api = self.kc.build(name, realm)

        print('** Authentication flow fetching: ', name)

        kc_objects = self.all(authentication_api)

        store_api.add_child("flows")  # auth/flows
        counter = 0
        for kc_object in kc_objects:
            store_api.add_child(normalize(kc_object[identifier]))  # auth/flows/authentication_name
            store_api.store_one(kc_object, identifier)

            executors = authentication_api.executions(kc_object).all()
            self._update_executors_with_config(executors)
            store_api.add_child('executors')  # auth/flows/authentication_name/executions
            store_api.store_one_with_alias('executors', executors)

            store_api.remove_last_child()  # auth/flows/auth_name/*executions*
            store_api.remove_last_child()  # auth/flows/*authentication_name*
            counter += 1
        store_api.remove_last_child()  # auth/flows

    def _update_executors_with_config(self, executors):
        """
        Input executors are modified.
        UUID of config object is replaced with config object data
        Config object alias is not unique, so we do not use it for filename,
        and config object is not stored into dedicated file.
        """
        for executor in executors:
            auth_config = self._get_executor_config(executor)
            if not auth_config:
                continue
            executor["authenticationConfigData"] = auth_config
            executor.pop("authenticationConfig")

    def _get_executor_config(self, executor):
        # executor - a flow or execution
        if not executor["configurable"]:
            return {}
        if "authenticationConfig" not in executor:
            # is configurable, but it was not configured
            return {}
        auth_config_id = executor["authenticationConfig"]
        auth_config_api = self.kc.build("authentication/config", self.realm)
        auth_config = auth_config_api.get(auth_config_id).verify().resp().json()
        return auth_config

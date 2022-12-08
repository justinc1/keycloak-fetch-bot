import logging
from copy import copy

from kcfetcher.utils import RH_SSO_VERSIONS_7_4

logger = logging.getLogger(__name__)


# This will fetch only realm data; it will not recurse to child objects.
class RealmFetch():
    def __init__(self, kc):
        self.kc = kc

    def fetch_one(self, store_api, realm):
        # realm - unmodified response from API
        print('publishing: ', realm["id"])

        # remove attributes that are stored in some other directory
        realm_min = copy(realm)
        if "identityProviders" in realm_min:
            # KC 9.0, RH SSO 7.4 have identityProviders set only if it is not empty
            # compound_profile_version = self.kc.server_info.profile_name + " "
            # compound_profile_version += ".".join(self.kc.server_info.version.split(".")[:2])
            # assert compound_profile_version in ["community 15.0", "community 18.0", "product 7.5", "product 7.6"]
            realm_min.pop("identityProviders")
        # defaultRoles list is unordered. We want it sorted in json file.
        if self.kc.server_info_compound_profile_version() in RH_SSO_VERSIONS_7_4:
            assert "defaultRoles" in realm_min
            realm_min["defaultRoles"] = sorted(realm_min["defaultRoles"])
        realm_min["enabledEventTypes"] = sorted(realm_min["enabledEventTypes"])

        store_api.store_one(realm_min, 'realm')

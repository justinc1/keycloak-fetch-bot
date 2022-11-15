import logging
from copy import copy

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
        realm_min.pop("identityProviders")

        store_api.store_one(realm_min, 'realm')

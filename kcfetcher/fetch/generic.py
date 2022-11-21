import logging
# https://setuptools.pypa.io/en/stable/userguide/datafiles.html#accessing-data-files-at-runtime
# from importlib.resources import files  # py3.10 only
from importlib_resources import files

logger = logging.getLogger(__name__)


def get_blacklist():
    blacklist_path = files('kcfetcher.data').joinpath('kcfetcher_blacklist')
    return open(blacklist_path).read().split('\n')


class GenericFetch:
    def __init__(self, kc, resource_name, resource_id="", realm=""):
        self.kc = kc
        self.resource_name = resource_name
        self.id = resource_id
        self.realm = realm
        self.black_list = get_blacklist()

    def fetch(self, store_api):
        name = self.resource_name
        identifier = self.id

        print('--> fetching: ', name)

        kc_objects = self._get_data()
        store_api.store(kc_objects, identifier)

    def _get_data(self):
        kc = self.kc.build(self.resource_name, self.realm)
        kc_objects = self.all(kc)
        return kc_objects

    def all(self, kc):
        all_objects = kc.all()
        objects = []
        for obj in all_objects:
            if self.id not in obj:
                # Likely we want to store such object, but it could be typo in code ("name" vs "namee").
                # Better check.
                logger.error(f"No attribute {self.id} in object, realm={self.realm} resource_name={self.resource_name}. OBJ: clientId={obj.get('clientId')} obj={obj}")
            if obj[self.id] in self.black_list:
                continue
            objects.append(obj)
        return objects

# https://setuptools.pypa.io/en/stable/userguide/datafiles.html#accessing-data-files-at-runtime
# from importlib.resources import files  # py3.10 only
from importlib_resources import files


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
        realm = self.realm

        print('--> fetching: ', name)

        kc = self.kc.build(name, realm)
        kc_objects = self.all(kc)
        store_api.store(kc_objects, identifier)

    def all(self, kc):
        return filter(lambda fn: not fn[self.id] in self.black_list, kc.all())

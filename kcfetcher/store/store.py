import json

from kcfetcher.utils import make_folder, remove_ids, normalize

class Store:
    def __init__(self, path=''):
        self.path = path.split('/')

    def add_child(self, child_name):
        self.path.append(child_name.replace(' ', '_').lower())

    def remove_last_child(self):
        self.path.pop()
        return self

    def __get_relative_path(self):
        return './' + '/'.join(self.path)

    def store_one_with_alias(self, alias, data):
        path = self.__get_relative_path()
        make_folder(path)

        file = open(path + '/' + normalize(alias) + '.json', 'w')
        data = remove_ids(data)
        json.dump(data, file, indent=4, sort_keys=True)
        file.close()

    def store_one(self, data, identifier):
        self.store_one_with_alias(data[identifier], data)

    def store(self, data, identifier):
        for entry in data:
            self.store_one_with_alias(entry[identifier], entry)
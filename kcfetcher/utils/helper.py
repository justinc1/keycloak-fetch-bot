import os
import shutil

from kcapi import OpenID, Keycloak


def remove_ids(kc_object={}):
    if isinstance(kc_object, list):
        for index in range(len(kc_object)):
            kc_object[index] = remove_ids(kc_object[index])
        return kc_object

    for key in list(kc_object):
        if key == 'id' or key == 'flowId':
            del kc_object[key]
            continue

        if isinstance(kc_object[key], dict):
            remove_ids(kc_object[key])
            continue

    return kc_object


def login(endpoint, user, password, read_token_from_file=False):
    token = None
    if not read_token_from_file:
        token = OpenID.createAdminClient(user, password, endpoint).getToken()
    else:
        token = open('./token').read()
    return Keycloak(token, endpoint)


def normalize(identifier=""):
    identifier = identifier.lower().replace('/', '_').replace(' ', '_')
    return identifier.replace('=', '_').replace(',', '_')


def make_folder(name):
    if not os.path.isdir(name):
        os.makedirs(name)


def remove_folder(name):
    if os.path.isdir(name):
        shutil.rmtree(name)

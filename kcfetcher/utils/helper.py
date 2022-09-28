import os
import shutil

from kcapi import OpenID, Keycloak


def remove_ids(kc_object={}):
    # simple scalar values are safe to return
    if isinstance(kc_object, (str, bool, int, float)):
        return kc_object

    # each list element needs to be cleaned recursively
    if isinstance(kc_object, list):
        return [remove_ids(obj) for obj in kc_object]

    # each dict element needs to be cleaned recursively
    assert isinstance(kc_object, dict)
    kc_object_cleaned = dict()
    for key in list(kc_object):
        if key in ['id', 'flowId']:
            # drop it
            continue
        # keep (the cleaned version of) it
        kc_object_cleaned[key] = remove_ids(kc_object[key])
    return kc_object_cleaned


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

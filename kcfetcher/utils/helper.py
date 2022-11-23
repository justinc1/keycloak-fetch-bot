import os
import re
import shutil
from copy import copy

from kcapi import OpenID, Keycloak

RH_SSO_VERSIONS_7_4 = [
    "product 7.4",
    "community 9.0",
]
RH_SSO_VERSIONS_7_5 = [
    "product 7.5",
    "community 15.0",
]


def find_in_list(objects, **kwargs):
    # objects - list of dict
    # kwargs - key=value, used to find one object
    key = list(kwargs.keys())[0]
    value = kwargs[key]
    for obj in objects:
        if key in obj and obj[key] == value:
            return obj

def minimize_role_representation(full_role, realms, clients):
    """
    This is used to get a minimal role representation.
    It contains just enough data that sub-role of the composite role can be found.
    Or that role referred by client scope mapping can be found.

    We replace attribute containerId with containerName:
    - For client roles, containerId contains client.id, containerName is set to client.clientId.
    - For realm roles, containerId contains realm.id, containerName is set to realm.realm.

    Complete role representation is stored in realm /roles or client/roles/.
    """
    containerId = full_role["containerId"]
    if full_role["clientRole"]:
        container_name = find_in_list(clients, id=containerId)["clientId"]
    else:
        container_name = find_in_list(realms, id=containerId)["realm"]
    return dict(
        name=full_role["name"],
        clientRole=full_role["clientRole"],
        containerName=container_name,
    )


def remove_ids(kc_object={}):
    # simple scalar values are safe to return
    if isinstance(kc_object, (str, bool, int, float)):
        return kc_object

    # each list element needs to be cleaned recursively
    if isinstance(kc_object, list):
        return [remove_ids(obj) for obj in kc_object]

    # each dict element needs to be cleaned recursively
    assert isinstance(kc_object, dict)
    return {key: remove_ids(kc_object[key]) for key in kc_object if key not in ['id', 'flowId']}


def sort_json(data):
    # We want to sort:
    # - list of dict, sort by "name" attribute
    # - dict of dict, sort by "name" attribute
    # We sort by name, clientId, maybe more.

    dd = copy(data)

    # simple scalar values are safe to return
    if isinstance(dd, (str, bool, int, float)):
        return dd

    if isinstance(dd, list):
        if not dd:
            return dd
        if not isinstance(dd[0], dict):
            return dd
        # we have list of dict
        key = "name"
        if key not in dd[0]:
            return dd
        # composites_sorted = sorted(data["composites"], key=lambda obj: obj["name"])
        dd_sorted = sorted(dd, key=lambda obj: obj[key])
        return dd_sorted

    # sort allowed-protocol-mapper-types
    assert isinstance(dd, dict)
    if "config" in dd and \
            isinstance(dd["config"], dict) and \
            "allowed-protocol-mapper-types" in dd["config"] and \
            isinstance(dd["config"]["allowed-protocol-mapper-types"], list):
        dd["config"]["allowed-protocol-mapper-types"] = sorted(dd["config"]["allowed-protocol-mapper-types"])

    # sort client.json - defaultClientScopes
    if "defaultClientScopes" in dd and \
            isinstance(dd["defaultClientScopes"], list):
        dd["defaultClientScopes"] = sorted(dd["defaultClientScopes"])

    assert isinstance(dd, dict)
    for kk in dd:
        vv_sorted = sort_json(dd[kk])
        dd[kk] = vv_sorted
    return dd


def login(endpoint, user, password, read_token_from_file=False):
    token = None
    if not read_token_from_file:
        token = OpenID.createAdminClient(user, password, endpoint).getToken()
    else:
        token = open('./token').read()
    return Keycloak(token, endpoint)


def normalize(identifier=""):
    identifier = identifier.lower()
    not_allowed_regex = r"[^a-z0-9.\-_]"
    return re.sub(not_allowed_regex, "_", identifier)


def make_folder(name):
    if not os.path.isdir(name):
        os.makedirs(name)


def remove_folder(name):
    if os.path.isdir(name):
        shutil.rmtree(name)

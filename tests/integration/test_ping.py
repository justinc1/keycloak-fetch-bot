import os
from copy import copy

from kcapi import OpenID, Keycloak


class TestOK:
    @staticmethod
    def test_ok():
        assert True


class BaseTestClass:
    # update os.environ with env.env file
    _env_file = "env.env"
    _os_environ_before = {}

    @classmethod
    def setup_class(cls):
        env_lines = open("env.env").readlines()
        env_lines = [el for el in env_lines if el.strip()]
        cls._os_environ_before = copy(os.environ)
        for line in env_lines:
            kk, vv = line.strip().split('=', 1)
            os.environ[kk] = vv

    @classmethod
    def teardown_class(cls):
        env_lines = open("env.env").readlines()
        env_lines = [el for el in env_lines if el.strip()]
        for line in env_lines:
            kk, vv = line.strip().split('=', 1)
            os.environ[kk] = cls._os_environ_before[kk]


# Check test SSO server is reachable, and we can login.
class TestSsoServer(BaseTestClass):
    @staticmethod
    def test_can_login():
        server = os.environ['SSO_API_URL']
        user = os.environ['SSO_API_USERNAME']
        password = os.environ['SSO_API_PASSWORD']
        token = OpenID.createAdminClient(user, password, server).getToken()
        kc = Keycloak(token, server)
        realms = kc.admin()
        # realm name is not empty
        assert realms.all()[0]['realm']

import os
from kcapi import OpenID, Keycloak


class TestOK:
    @staticmethod
    def test_ok():
        assert True


# Check test SSO server is reachable, and we can login.
class TestSsoServer:
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

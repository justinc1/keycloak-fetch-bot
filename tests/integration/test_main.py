import glob
import json
import os

from pytest_unordered import unordered

from kcfetcher.utils import remove_folder
from kcfetcher.main import run


# Does main produce expected result.
# A new subdir is created for master realm, and it must contain some json files etc.
from tests.integration.test_ping import BaseTestClass


class TestMain(BaseTestClass):
    @staticmethod
    def test_main():
        datadir = './output/ci/outd/'
        remove_folder(datadir)
        assert not os.path.exists(datadir)

        run(datadir)

        # only check directories, files and their content is covered in specific tests.
        assert unordered(glob.glob('**/', root_dir=datadir, recursive=True)) == [
            'master/',
            'master/authentication/',
            'master/authentication/required-actions/',
            'master/authentication/flows/',
            'master/authentication/flows/registration/',
            'master/authentication/flows/registration/executors/',
            'master/authentication/flows/browser/',
            'master/authentication/flows/browser/executors/',
            'master/authentication/flows/reset_credentials/',
            'master/authentication/flows/reset_credentials/executors/',
            'master/authentication/flows/http_challenge/',
            'master/authentication/flows/http_challenge/executors/',
            'master/authentication/flows/direct_grant/',
            'master/authentication/flows/direct_grant/executors/',
            'master/authentication/flows/clients/',
            'master/authentication/flows/clients/executors/',
            'master/authentication/flows/docker_auth/',
            'master/authentication/flows/docker_auth/executors/',
            'master/authentication/flows/first_broker_login/',
            'master/authentication/flows/first_broker_login/executors/',
            'master/roles/',
            'master/clients/',
            'master/clients/client-1/',
            'master/clients/client-1/roles/',
            'master/clients/client-1/client-scopes/',
            'master/clients/client-0/',
            'master/clients/client-0/roles/',
            'master/clients/client-0/client-scopes/',
            'master/client-scopes/',
            'master/client-scopes/default/',
            # 'master/components/',  # emtpy dir is not created
            'master/client-registration-policies/',
            'master/client-registration-policies/anonymous/',
            'master/client-registration-policies/authenticated/',
            'ci0-realm/',
            'ci0-realm/authentication/',
            'ci0-realm/authentication/required-actions/',
            'ci0-realm/authentication/flows/',
            'ci0-realm/authentication/flows/registration/',
            'ci0-realm/authentication/flows/registration/executors/',
            'ci0-realm/authentication/flows/browser/',
            'ci0-realm/authentication/flows/browser/executors/',
            'ci0-realm/authentication/flows/ci0-auth-flow-generic/',
            'ci0-realm/authentication/flows/ci0-auth-flow-generic/executors/',
            'ci0-realm/authentication/flows/reset_credentials/',
            'ci0-realm/authentication/flows/reset_credentials/executors/',
            'ci0-realm/authentication/flows/http_challenge/',
            'ci0-realm/authentication/flows/http_challenge/executors/',
            'ci0-realm/authentication/flows/direct_grant/',
            'ci0-realm/authentication/flows/direct_grant/executors/',
            'ci0-realm/authentication/flows/clients/',
            'ci0-realm/authentication/flows/clients/executors/',
            'ci0-realm/authentication/flows/docker_auth/',
            'ci0-realm/authentication/flows/docker_auth/executors/',
            'ci0-realm/authentication/flows/first_broker_login/',
            'ci0-realm/authentication/flows/first_broker_login/executors/',
            'ci0-realm/groups/',
            'ci0-realm/user-federations/',
            'ci0-realm/user-federations/ci0-uf0-ldap/',
            'ci0-realm/user-federations/ci0-uf0-ldap/mappers/',
            'ci0-realm/user-federations/ci0-uf1-ldap/',
            'ci0-realm/user-federations/ci0-uf1-ldap/mappers/',
            'ci0-realm/user-federations/ci0-uf3-kerberos/',
            'ci0-realm/user-federations/ci0-uf2-kerberos/',
            'ci0-realm/identity-provider/',
            'ci0-realm/identity-provider/ci0-idp-saml-0/',
            'ci0-realm/identity-provider/ci0-idp-saml-0/mappers/',
            'ci0-realm/identity-provider/ci0-idp-saml-1/',
            'ci0-realm/identity-provider/ci0-idp-saml-1/mappers/',
            'ci0-realm/roles/',
            'ci0-realm/clients/',
            'ci0-realm/clients/client-0/',
            'ci0-realm/clients/client-0/client-scopes/',
            'ci0-realm/clients/client-0/roles/',
            'ci0-realm/clients/client-1/',
            'ci0-realm/clients/client-1/client-scopes/',
            'ci0-realm/clients/client-1/roles/',
            'ci0-realm/clients/client-2/',
            'ci0-realm/clients/client-2/client-scopes/',
            'ci0-realm/clients/client-2/roles/',
            'ci0-realm/clients/client-3/',
            'ci0-realm/clients/client-3/client-scopes/',
            'ci0-realm/client-scopes/',
            'ci0-realm/client-scopes/default/',
            # 'ci0-realm/components/',  # emtpy dir is not created
            'ci0-realm/client-registration-policies/',
            'ci0-realm/client-registration-policies/anonymous/',
            'ci0-realm/client-registration-policies/authenticated/',
        ]

        assert os.path.isfile(os.path.join(datadir, "master/master.json"))
        data = json.load(open(os.path.join(datadir, "master/master.json")))
        assert "master" == data["realm"]

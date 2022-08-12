import json
import os
from copy import copy

from kcfetcher.utils import remove_folder
from kcfetcher.main import run


# Does main produce expected result.
# A new subdir is created for master realm, and it must contain some json files etc.
class TestMain:
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

    @staticmethod
    def test_main():
        output_dir = './output/ci/outd/'
        remove_folder(output_dir)
        assert not os.path.exists(output_dir)

        run(output_dir)

        assert os.path.isdir(output_dir)
        assert os.path.isdir(os.path.join(output_dir, "master"))
        assert os.path.isdir(os.path.join(output_dir, "master/authentication"))
        assert os.path.isdir(os.path.join(output_dir, "master/authentication/browser"))
        assert os.path.isdir(os.path.join(output_dir, "master/authentication/clients"))
        assert os.path.isdir(os.path.join(output_dir, "master/clients"))
        assert os.path.isdir(os.path.join(output_dir, "master/components"))
        assert os.path.isdir(os.path.join(output_dir, "master/roles"))

        assert os.path.isfile(os.path.join(output_dir, "master/master.json"))
        data = json.load(open(os.path.join(output_dir, "master/master.json")))
        assert "master" == data["realm"]

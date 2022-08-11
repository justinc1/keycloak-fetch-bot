import json
import os
from kcfetcher.main import remove_folder, make_folder, run


# Does main produce expected result.
# A new subdir is created for master realm, and it must contain some json files etc.
class TestMain:
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

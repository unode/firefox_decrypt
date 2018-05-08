# -*- coding: utf-8 -*-

import os
from subprocess import check_output


class Test:
    def __init__(self):
        self.testdir = os.path.realpath(os.path.dirname(os.path.dirname(__file__)))

    def run(self, *args, **kwargs):
        return check_output(*args, **kwargs)

    def get_password(self):
        with open(os.path.join(self.get_test_data(), "master_password")) as fh:
            return fh.read()

    def get_script(self):
        return ["python", "{}/../firefox_decrypt.py".format(self.testdir)]

    def get_test_data(self):
        return os.path.join(self.testdir, "test_data")

    def _get_dir_data(self, subdir, target):
        with open(os.path.join(self.get_test_data(), subdir, "{}.{}".format(target, subdir[:-1]))) as fh:
            return fh.read()

    def get_user_data(self, user):
        return self._get_dir_data("users", user)

    def get_output_data(self, output):
        return self._get_dir_data("outputs", output)

    def get_internal_version(self):
        with open(os.path.join(self.get_test_data(), "..", "CHANGELOG.md")) as fh:
            for line in fh:
                if line.startswith("###") and "." in line:
                    return line.strip("#\n ")

    def remove_log_date_time(self):
        raise NotImplementedError()


lib = Test()

if __name__ == "__main__":
    pass

# vim: ai sts=4 et sw=4

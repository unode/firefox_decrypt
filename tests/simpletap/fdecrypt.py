# -*- coding: utf-8 -*-

import os
import sys
from subprocess import check_output, STDOUT, CalledProcessError

PY3 = sys.version_info.major > 2


class Test:
    def __init__(self):
        self.testdir = os.path.realpath(os.path.dirname(os.path.dirname(__file__)))

    def run(self, cmd, stdin=None, stderr=STDOUT):
        # Ideally we would use encoding='utf8' but this argument is only PY-3.5+
        output = check_output(cmd, stdin=stdin, stderr=stderr)

        if PY3:
            output = output.decode("utf8")

        return output

    def run_error(self, cmd, returncode, stdin=None, stderr=STDOUT):
        # Ideally we would use encoding='utf8' but this argument is only PY-3.5+
        try:
            output = self.run(cmd, stdin, stderr)
        except CalledProcessError as e:
            if e.returncode != returncode:
                raise ValueError("Expected exit code {} but saw {}".format(returncode, e.returncode))
            else:
                output = e.output

        return output

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

    def remove_full_pwd(self, output):
        return output.replace(os.path.join(self.testdir, ''), '')

    def remove_log_date_time(self, input):
        output = []
        for line in input.split('\n'):
            output.append(line.split(' ', 2)[-1])

        return '\n'.join(output)


lib = Test()

if __name__ == "__main__":
    pass

# vim: ai sts=4 et sw=4

# -*- coding: utf-8 -*-

import os
import re
import datetime
from subprocess import run, CalledProcessError, PIPE, STDOUT


class Test:
    def __init__(self):
        self.testdir = os.path.realpath(os.path.dirname(os.path.dirname(__file__)))

    def run(self, cmd, stdin=None, stderr=STDOUT, workdir=None):
        p = run(cmd, check=True, encoding="utf8", cwd=workdir,
                input=stdin, stdout=PIPE, stderr=stderr)

        return p.stdout

    def run_error(self, cmd, returncode, stdin=None, stderr=STDOUT, workdir=None):
        try:
            output = self.run(cmd, stdin=stdin, stderr=stderr, workdir=workdir)
        except CalledProcessError as e:
            if e.returncode != returncode:
                raise ValueError("Expected exit code {} but saw {}".format(returncode, e.returncode))
            else:
                output = e.stdout

        return output

    def get_password(self):
        with open(os.path.join(self.get_test_data(), "master_password")) as fh:
            return fh.read()

    def get_script(self):
        return ["python3", "{}/../firefox_decrypt.py".format(self.testdir)]

    def get_test_data(self):
        return os.path.join(self.testdir, "test_data")

    def _get_dir_data(self, subdir, target):
        with open(os.path.join(self.get_test_data(), subdir, "{}.{}".format(target, subdir[:-1]))) as fh:
            return fh.read()

    def get_user_data(self, target):
        return self._get_dir_data("users", target)

    def get_output_data(self, target):
        return self._get_dir_data("outputs", target)

    def get_internal_version(self):
        with open(os.path.join(self.testdir, "..", "CHANGELOG.md")) as fh:
            for line in fh:
                if line.startswith("###") and "." in line:
                    return line.strip("# ")

    def remove_full_pwd(self, output):
        return output.replace(os.path.join(self.testdir, ''), '')

    def remove_log_date_time(self, input, dropmatches=False):
        output = []
        date = str(datetime.datetime.now().date())
        for line in input.split('\n'):
            if line.startswith(date):
                if not dropmatches:
                    output.append(line.split(' ', 2)[-1])
            else:
                output.append(line)

        return '\n'.join(output)

    def grep(self, pattern, output, context=0):
        r = re.compile(pattern)
        lines = output.split('\n')

        acc = []
        for i in range(len(lines)):
            if r.search(lines[i]):
                acc.extend(lines[i-context:1+i+context])

        return '\n'.join(acc) + '\n'


lib = Test()

if __name__ == "__main__":
    pass

# vim: ai sts=4 et sw=4

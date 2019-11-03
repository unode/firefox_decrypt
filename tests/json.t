#!/usr/bin/env python3

import os
import json
import unittest
import subprocess
import re
from simpletap.fdecrypt import lib


class TestJSON(unittest.TestCase):
    def setUp(self):
        self.test = lib.get_test_data()
        self.pwd = lib.get_password()

    def validate_one(self, userkey, grepkey, output):
        data = json.loads(output)
        expected_data = json.loads(lib.get_user_data(userkey))
        for entry in data:
            if grepkey not in entry['user']:
                continue

            self.assertDictEqual(entry, expected_data)
            break

    def validate_indentation(self, out):
        data = json.loads(out)
        indent_map = {
            '': 2,
            '  ': 2 * len(data),
            '    ': sum(len(element) for element in data)
            }
        indent_counts = {}
        for line in out.strip().splitlines():
            m = re.match(r'^(\s*)', line)
            if m:
                indent = m.group(1)
                try:
                    indent_counts[indent] += 1
                except KeyError:
                    indent_counts[indent] = 1

        self.assertDictEqual(indent_counts, indent_map)

    def validate_default(self, out):
        self.validate_one("doesntexist_json_pretty", "doesntexist", out)
        self.validate_one("onemore_json_pretty", "onemore", out)
        self.validate_one("complex_json_pretty", "cömplex", out)
        self.validate_one("jamie_json_pretty", "jãmïe", out)

    def validate_pretty(self, out):
        self.validate_one("doesntexist_json_pretty", "doesntexist", out)
        self.validate_one("onemore_json_pretty", "onemore", out)
        self.validate_one("complex_json_pretty", "cömplex", out)
        self.validate_one("jamie_json_pretty", "jãmïe", out)
        self.validate_indentation(out)

    def test_firefox_20_default(self):
        test = os.path.join(self.test, "test_profile_firefox_20")

        cmd = lib.get_script() + [test, "--format", "json"]
        output = lib.run(cmd, stdin=self.pwd, stderr=subprocess.DEVNULL)
        self.validate_default(output)

    def test_firefox_20_pretty(self):
        test = os.path.join(self.test, "test_profile_firefox_20")

        cmd = lib.get_script() + [test, "--format", "json", "--pretty"]
        output = lib.run(cmd, stdin=self.pwd, stderr=subprocess.DEVNULL)
        self.validate_pretty(output)

    def test_firefox_46_default(self):
        test = os.path.join(self.test, "test_profile_firefox_46")

        cmd = lib.get_script() + [test, "--format", "json"]
        output = lib.run(cmd, stdin=self.pwd, stderr=subprocess.DEVNULL)
        self.validate_default(output)

    def test_firefox_46_pretty(self):
        test = os.path.join(self.test, "test_profile_firefox_46")

        cmd = lib.get_script() + [test, "--format", "json", "--pretty"]
        output = lib.run(cmd, stdin=self.pwd, stderr=subprocess.DEVNULL)
        self.validate_pretty(output)

    def test_firefox_59_default(self):
        test = os.path.join(self.test, "test_profile_firefox_59")

        cmd = lib.get_script() + [test, "--format", "json"]
        output = lib.run(cmd, stdin=self.pwd, stderr=subprocess.DEVNULL)
        self.validate_default(output)

    def test_firefox_59_pretty(self):
        test = os.path.join(self.test, "test_profile_firefox_59")

        cmd = lib.get_script() + [test, "--format", "json", "--pretty"]
        output = lib.run(cmd, stdin=self.pwd, stderr=subprocess.DEVNULL)
        self.validate_pretty(output)

    def test_firefox_nopassword_default(self):
        test = os.path.join(self.test, "test_profile_firefox_nopassword")

        cmd = lib.get_script() + [test, "-n", "--format", "json"]
        output = lib.run(cmd, stderr=subprocess.DEVNULL)
        self.validate_default(output)

    def test_firefox_nopassword_pretty(self):
        test = os.path.join(self.test, "test_profile_firefox_nopassword")

        cmd = lib.get_script() + [test, "-n", "--format", "json", "--pretty"]
        output = lib.run(cmd, stderr=subprocess.DEVNULL)
        self.validate_pretty(output)


if __name__ == "__main__":
    from simpletap import TAPTestRunner
    unittest.main(testRunner=TAPTestRunner())

# vim: ai sts=4 et sw=4

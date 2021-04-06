#!/usr/bin/env python3

import os
import unittest
from simpletap.fdecrypt import lib


class TestJSON(unittest.TestCase):
    def setUp(self):
        self.test = lib.get_test_data()
        self.pwd = lib.get_password()

    def validate_one(self, userkey, grepkey, output):
        expected = lib.get_user_data(userkey)

        expected = lib.remove_log_date_time(expected, dropmatches=True)
        matches = lib.remove_log_date_time(output, dropmatches=True)

        self.assertEqual(matches, expected)

    def validate_default(self, out):
        self.validate_one("header_json_default", '"password"', out)
        self.validate_one("doesntexist_json_default", "doesntexist", out)
        self.validate_one("onemore_json_default", "onemore", out)
        self.validate_one("complex_json_default", "cömplex", out)
        self.validate_one("jamie_json_default", "jãmïe", out)

    def test_firefox_20_default(self):
        test = os.path.join(self.test, "test_profile_firefox_20")

        cmd = lib.get_script() + [test, "--format", "json"]
        output = lib.run(cmd, stdin=self.pwd, stderr=None)
        self.validate_default(output)

    def test_firefox_46_default(self):
        test = os.path.join(self.test, "test_profile_firefox_46")

        cmd = lib.get_script() + [test, "--format", "json"]
        output = lib.run(cmd, stdin=self.pwd, stderr=None)
        self.validate_default(output)

    def test_firefox_nopassword_default(self):
        test = os.path.join(self.test, "test_profile_firefox_nopassword")

        cmd = lib.get_script() + [test, "-n", "--format", "json"]
        output = lib.run(cmd, stderr=None)
        self.validate_default(output)


if __name__ == "__main__":
    from simpletap import TAPTestRunner
    unittest.main(testRunner=TAPTestRunner())

# vim: ai sts=4 et sw=4

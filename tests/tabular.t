#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import unittest
from simpletap.fdecrypt import lib


class TestTabular(unittest.TestCase):
    def setUp(self):
        self.test = lib.get_test_data()
        self.pwd = lib.get_password()

    def validate_one(self, userkey, grepkey, output):
        expected = lib.get_user_data(userkey)
        matches = lib.grep(grepkey, output)

        self.assertEqual(matches, expected)

    def validate(self, out):
        self.validate_one("doesntexist_tabular", "doesntexist", out)
        self.validate_one("onemore_tabular", "onemore", out)
        self.validate_one("complex_tabular", "cömplex", out)
        self.validate_one("jamie_tabular", "jãmïe", out)

    def test_firefox_20(self):
        test = os.path.join(self.test, "test_profile_firefox_20")
        cmd = lib.get_script() + [test, "--tabular"]

        output = lib.run(cmd, stdin=self.pwd)
        self.validate(output)

    def test_firefox_46(self):
        test = os.path.join(self.test, "test_profile_firefox_46")
        cmd = lib.get_script() + [test, "--tabular"]

        output = lib.run(cmd, stdin=self.pwd)
        self.validate(output)

    def test_firefox_nopassword(self):
        test = os.path.join(self.test, "test_profile_firefox_nopassword")

        # Must run in non-interactive mode or password prompt will be shown
        cmd = lib.get_script() + [test, "--tabular", "-n"]

        output = lib.run(cmd)
        self.validate(output)


if __name__ == "__main__":
    from simpletap import TAPTestRunner
    unittest.main(testRunner=TAPTestRunner())

# vim: ai sts=4 et sw=4

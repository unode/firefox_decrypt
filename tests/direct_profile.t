#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import unittest
from simpletap.fdecrypt import lib


class TestDirectProfilePass(unittest.TestCase):
    def validate_one(self, userkey, grepkey, output):
        expected = lib.get_user_data(userkey)
        matches = lib.grep(grepkey, output, context=1)

        self.assertEqual(matches, expected)

    def validate(self, out):
        self.validate_one("doesntexist", "doesntexist", out)
        self.validate_one("onemore", "onemore", out)
        self.validate_one("complex", "cömplex", out)
        self.validate_one("jamie", "jãmïe", out)

    def run_firefox_with_password(self):
        cmd = lib.get_script() + [self.test]
        pwd = lib.get_password()

        output = lib.run(cmd, stdin=pwd)
        self.validate(output)

    def run_firefox_nopassword(self):
        # Must run in non-interactive mode or password prompt will be shown
        cmd = lib.get_script() + [self.test, "-n"]

        output = lib.run(cmd)
        self.validate(output)

    def test_firefox_20(self):
        self.test = os.path.join(lib.get_test_data(),
                                 "test_profile_firefox_20")
        self.run_firefox_with_password()

    def test_firefox_46(self):
        self.test = os.path.join(lib.get_test_data(),
                                 "test_profile_firefox_46")
        self.run_firefox_with_password()

    def test_firefox_non_ascii(self):
        self.test = os.path.join(lib.get_test_data(),
                                 "test_profile_firefox_LЮшр/")
        self.run_firefox_with_password()

    def test_firefox_nopass(self):
        self.test = os.path.join(lib.get_test_data(),
                                 "test_profile_firefox_nopassword")
        self.run_firefox_nopassword()


if __name__ == "__main__":
    from simpletap import TAPTestRunner
    unittest.main(testRunner=TAPTestRunner())

# vim: ai sts=4 et sw=4

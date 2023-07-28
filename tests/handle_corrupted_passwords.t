#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import unittest
from simpletap.fdecrypt import lib


class TestCorruptedPassword(unittest.TestCase):
    def validate_one(self, userkey, grepkey, output):
        expected = lib.get_user_data(userkey)
        # Ignore DEBUG/verbose information when looking for the specified key
        output = lib.grep("^(?!.*DEBUG).*$", output, context=0)
        matches = lib.grep(grepkey, output, context=1)

        self.assertEqual(matches, expected)

    def validate(self, out):
        self.validate_one("decryption_failed", "Username: .* decryption failed", out)
        self.validate_one("doesntexist", "doesntexist", out)
        self.validate_one("onemore", "onemore", out)
        self.validate_one("complex", "cömplex", out)
        self.validate_one("jamie", "jãmïe", out)

    def validate_exception(self, out):
        # error is "ValueError: Username/Password decryption (...) Credentials damaged (...)"
        err = "Credentials damaged or cert/key file mismatch."
        match = lib.grep(err, out)
        self.assertIn("ValueError: Username/Password", match)

    def validate_error(self, out):
        # error is "ERROR - Username/Password decryption (...) Credentials damaged (...)"
        err = "Credentials damaged or cert/key file mismatch."
        match = lib.grep(err, out)
        self.assertIn("ERROR - Username/Password", match)

    def run_firefox_nopassword(self, cmd):
        output = lib.run(cmd)
        self.validate(output)
        self.validate_exception(output)

    def run_firefox_nopassword_error(self, cmd):
        # returncode 17 is DECRYPTION_FAILED
        output = lib.run_error(cmd, returncode=17)
        self.validate_error(output)

    def test_corrupted_skip_firefox_114(self):
        self.test = os.path.join(lib.get_test_data(),
                                 "test_profile_firefox_nopassword_114")

        # Must run in non-interactive mode or password prompt will be shown
        cmd = lib.get_script() + [self.test, "-n", "--non-fatal-decryption", "-vv"]

        self.run_firefox_nopassword(cmd)

    def test_corrupted_firefox_114(self):
        self.test = os.path.join(lib.get_test_data(),
                                 "test_profile_firefox_nopassword_114")

        # Must run in non-interactive mode or password prompt will be shown
        cmd = lib.get_script() + [self.test, "-n"]

        self.run_firefox_nopassword_error(cmd)


if __name__ == "__main__":
    from simpletap import TAPTestRunner
    unittest.main(testRunner=TAPTestRunner(buffer=True), exit=False)

# vim: ai sts=4 et sw=4

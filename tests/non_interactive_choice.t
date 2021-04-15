#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from simpletap.fdecrypt import lib


class TestNonInteractiveChoice(unittest.TestCase):
    def validate_one(self, userkey, grepkey, output):
        expected = lib.get_user_data(userkey)
        matches = lib.grep(grepkey, output, context=1)

        self.assertEqual(matches, expected)

    def validate(self, out):
        self.validate_one("doesntexist", "doesntexist", out)
        self.validate_one("onemore", "onemore", out)
        self.validate_one("complex", "cömplex", out)
        self.validate_one("jamie", "jãmïe", out)

    @unittest.skipIf(lib.platform == "Windows",
                     "Windows DLL isn't backwards compatible")
    def test_firefox_20(self):
        cmd = lib.get_script() + [lib.get_test_data(), "-nc", "1"]
        pwd = lib.get_password()

        out = lib.run(cmd, stdin=pwd)
        self.validate(out)

    @unittest.skipIf(lib.platform == "Windows",
                     "Windows DLL isn't backwards compatible")
    def test_firefox_46(self):
        cmd = lib.get_script() + [lib.get_test_data(), "-nc", "2"]
        pwd = lib.get_password()

        out = lib.run(cmd, stdin=pwd)
        self.validate(out)

    def test_firefox_59(self):
        cmd = lib.get_script() + [lib.get_test_data(), "-nc", "4"]
        pwd = lib.get_password()

        out = lib.run(cmd, stdin=pwd)
        self.validate(out)

    @unittest.skipIf(lib.platform == "Windows",
                     "Windows DLL isn't backwards compatible")
    def test_firefox_nopass_46(self):
        cmd = lib.get_script() + [lib.get_test_data(), "-nc", "3"]

        out = lib.run(cmd)
        self.validate(out)

    def test_firefox_nopass_59(self):
        cmd = lib.get_script() + [lib.get_test_data(), "-nc", "6"]

        out = lib.run(cmd)
        self.validate(out)

    def test_firefox_missing_choice(self):
        cmd = lib.get_script() + [lib.get_test_data(), "-n"]

        out = lib.run_error(cmd, returncode=31)  # 31 is MISSING_CHOICE exit
        output = lib.remove_log_date_time(out)
        expected = lib.get_output_data("non_interactive_choice_missing")
        self.assertEqual(output, expected)


if __name__ == "__main__":
    from simpletap import TAPTestRunner
    unittest.main(testRunner=TAPTestRunner(buffer=True), exit=False)

# vim: ai sts=4 et sw=4

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from simpletap.fdecrypt import lib


class TestProfileIni(unittest.TestCase):
    def setUp(self):
        self.test = lib.get_test_data()
        self.pwd = lib.get_password()

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
        cmd = lib.get_script() + [self.test]
        choice = "1"
        payload = '\n'.join((choice, self.pwd))

        output = lib.run(cmd, stdin=payload)
        self.validate(output)

    @unittest.skipIf(lib.platform == "Windows",
                     "Windows DLL isn't backwards compatible")
    def test_firefox_46(self):
        cmd = lib.get_script() + [self.test]
        choice = "2"
        payload = '\n'.join((choice, self.pwd))

        output = lib.run(cmd, stdin=payload)
        self.validate(output)

    def test_firefox_59(self):
        cmd = lib.get_script() + [self.test]
        choice = "4"
        payload = '\n'.join((choice, self.pwd))

        output = lib.run(cmd, stdin=payload)
        self.validate(output)

    def test_firefox_non_ascii(self):
        cmd = lib.get_script() + [self.test]
        choice = "5"
        payload = '\n'.join((choice, self.pwd))

        output = lib.run(cmd, stdin=payload)
        self.validate(output)

    @unittest.skipIf(lib.platform == "Windows",
                     "Windows DLL isn't backwards compatible")
    def test_firefox_nopass_46(self):
        cmd = lib.get_script() + [self.test]
        payload = "3"

        output = lib.run(cmd, stdin=payload)
        self.validate(output)

    def test_firefox_nopass_59(self):
        cmd = lib.get_script() + [self.test]
        payload = "6"

        output = lib.run(cmd, stdin=payload)
        self.validate(output)


if __name__ == "__main__":
    from simpletap import TAPTestRunner
    unittest.main(testRunner=TAPTestRunner(buffer=True), exit=False)

# vim: ai sts=4 et sw=4

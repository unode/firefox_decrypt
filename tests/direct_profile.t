#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import unittest
from simpletap.fdecrypt import lib


class BaseTemplateDirectProfile(object):
    def validate(self, output):
        key = "doesntexist"
        expected = lib.get_user_data(key)
        matches = lib.grep(key, output, context=1)

        self.assertEqual(matches, expected)

        key = "onemore"
        expected = lib.get_user_data(key)
        matches = lib.grep(key, output, context=1)

        self.assertEqual(matches, expected)

        key = "cömplex"
        expected = lib.get_user_data("complex")
        matches = lib.grep(key, output, context=1)

        self.assertEqual(matches, expected)

        key = "jãmïe"
        expected = lib.get_user_data("jamie")
        matches = lib.grep(key, output, context=1)

        self.assertEqual(matches, expected)


class TemplateDirectProfilePass(BaseTemplateDirectProfile):
    def test_firefox(self):
        cmd = lib.get_script() + [self.test]
        pwd = lib.get_password()

        output = lib.run(cmd, stdin=pwd)
        self.validate(output)


class TemplateDirectProfileNoPass(BaseTemplateDirectProfile):
    def test_firefox(self):
        cmd = lib.get_script() + [self.test]

        output = lib.run(cmd)
        self.validate(output)


class TestDirectProfile20(unittest.TestCase, TemplateDirectProfilePass):
    def setUp(self):
        self.test = os.path.join(lib.get_test_data(),
                                 "test_profile_firefox_20")


class TestDirectProfile46(unittest.TestCase, TemplateDirectProfilePass):
    def setUp(self):
        self.test = os.path.join(lib.get_test_data(),
                                 "test_profile_firefox_46")


class TestDirectProfileNoPass(unittest.TestCase, TemplateDirectProfileNoPass):
    def setUp(self):
        self.test = os.path.join(lib.get_test_data(),
                                 "test_profile_firefox_nopassword")


if __name__ == "__main__":
    from simpletap import TAPTestRunner
    unittest.main(testRunner=TAPTestRunner())

# vim: ai sts=4 et sw=4

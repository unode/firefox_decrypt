#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import unittest
from simpletap.fdecrypt import lib


class TestDirectProfileNoPass(unittest.TestCase):
    def setUp(self):
        self.test = os.path.join(lib.get_test_data(),
                                 "test_profile_firefox_nopassword")

    def test_nopass(self):
        """specifying a passwordless profile directly should use the profile
        """
        cmd = lib.get_script() + [self.test]

        output = lib.run(cmd)

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


if __name__ == "__main__":
    from simpletap import TAPTestRunner
    unittest.main(testRunner=TAPTestRunner())

# vim: ai sts=4 et sw=4

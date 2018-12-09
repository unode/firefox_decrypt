#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import unittest
from simpletap.fdecrypt import lib


class BaseTemplateSingleProfile(object):
    def test_listing_from_single_profile(self):
        test = os.path.join(lib.get_test_data(), self.test_profile)
        cmd = lib.get_script() + ["-l", test]

        expected = lib.get_output_data(self.output_data)
        expected_exitcode = 2

        output = lib.remove_full_pwd(
            lib.remove_log_date_time(
                lib.run_error(cmd, returncode=expected_exitcode)))

        self.assertEqual(output, expected)


class TestSingleProfile20(unittest.TestCase, BaseTemplateSingleProfile):
    def setUp(self):
        self.test_profile = "test_profile_firefox_20"
        self.output_data = "list_single_20"


class TestSingleProfile46(unittest.TestCase, BaseTemplateSingleProfile):
    def setUp(self):
        self.test_profile = "test_profile_firefox_46"
        self.output_data = "list_single_46"


if __name__ == "__main__":
    from simpletap import TAPTestRunner
    unittest.main(testRunner=TAPTestRunner())

# vim: ai sts=4 et sw=4

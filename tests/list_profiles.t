#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import unittest
from simpletap.fdecrypt import lib


class TestListProfiles(unittest.TestCase):
    def test_listing_profiles(self):
        """list profiles should show the profile list"""
        cmd = lib.get_script() + ["-l", lib.get_test_data()]

        output = lib.run(cmd)
        expected = lib.get_output_data("list")

        self.assertEqual(output, expected)

    def test_listing_single_profiles(self):
        """list profiles should fail if provided a single profile"""
        test = os.path.join(lib.get_test_data(),
                            "test_profile_firefox_nopassword")
        cmd = lib.get_script() + ["-l", test]

        output = lib.run_error(cmd, returncode=2)
        output = lib.grep("ERROR", output)
        output = lib.remove_log_date_time(output)
        expected = lib.get_output_data("list_fail")

        self.assertEqual(output, expected)


if __name__ == "__main__":
    from simpletap import TAPTestRunner
    unittest.main(testRunner=TAPTestRunner(buffer=True), exit=False)

# vim: ai sts=4 et sw=4

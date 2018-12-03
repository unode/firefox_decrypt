#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import unittest
from simpletap.fdecrypt import lib


class TestSingleProfile20(unittest.TestCase):
    def test_listing_from_single_profile(self):
        """list profiles should show the profile list"""
        test = os.path.join(lib.get_test_data(), "test_profile_firefox_46")
        cmd = lib.get_script() + ["-l", test]

        expected = lib.get_output_data("list_single_46")
        expected_exitcode = 2

        output = lib.remove_full_pwd(
            lib.remove_log_date_time(
                lib.run_error(cmd, returncode=expected_exitcode)))

        self.assertEqual(output, expected)


if __name__ == "__main__":
    from simpletap import TAPTestRunner
    unittest.main(testRunner=TAPTestRunner())

# vim: ai sts=4 et sw=4

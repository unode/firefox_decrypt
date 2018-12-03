#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from simpletap.fdecrypt import lib


class TestListProfiles(unittest.TestCase):
    def test_listing_profiles(self):
        """list profiles should show the profile list"""
        cmd = lib.get_script() + ["-l", lib.get_test_data()]

        output = lib.run(cmd)
        expected = lib.get_output_data("list")

        self.assertEqual(output, expected)


if __name__ == "__main__":
    from simpletap import TAPTestRunner
    unittest.main(testRunner=TAPTestRunner())

# vim: ai sts=4 et sw=4

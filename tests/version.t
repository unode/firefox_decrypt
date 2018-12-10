#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from simpletap.fdecrypt import lib


class TestVersion(unittest.TestCase):
    def test_version(self):
        cmd = lib.get_script() + ["--version"]

        output = lib.run(cmd, workdir="/")
        expected = lib.get_internal_version()

        self.assertEqual(output, expected)


if __name__ == "__main__":
    from simpletap import TAPTestRunner
    unittest.main(testRunner=TAPTestRunner())

# vim: ai sts=4 et sw=4

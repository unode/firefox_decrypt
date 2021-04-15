#!/usr/bin/env python3

import os
import unittest
from simpletap.fdecrypt import lib


class TestCSV(unittest.TestCase):
    def setUp(self):
        self.test = lib.get_test_data()
        self.pwd = lib.get_password()

    def validate_one(self, userkey, grepkey, output):
        expected = lib.get_user_data(userkey)
        matches = lib.grep(grepkey, output)

        self.assertEqual(matches, expected)

    def validate_default(self, out):
        self.validate_one("header_csv_default", '"password"', out)
        self.validate_one("doesntexist_csv_default", "doesntexist", out)
        self.validate_one("onemore_csv_default", "onemore", out)
        self.validate_one("complex_csv_default", "cömplex", out)
        self.validate_one("jamie_csv_default", "jãmïe", out)

    def validate_tabular(self, out):
        self.validate_one("header_csv_tabular", "'password'", out)
        self.validate_one("doesntexist_tabular", "doesntexist", out)
        self.validate_one("onemore_tabular", "onemore", out)
        self.validate_one("complex_tabular", "cömplex", out)
        self.validate_one("jamie_tabular", "jãmïe", out)

    def validate_semicol(self, out):
        self.validate_one("header_csv_semicol_singlequot", "'password'", out)
        self.validate_one("doesntexist_csv_semicol_singlequot", "doesntexist", out)
        self.validate_one("onemore_csv_semicol_singlequot", "onemore", out)
        self.validate_one("complex_csv_semicol_singlequot", "cömplex", out)
        self.validate_one("jamie_csv_semicol_singlequot", "jãmïe", out)

    def validate_vertbar(self, out):
        self.validate_one("header_csv_tab_vertbar", r"\|password\|", out)
        self.validate_one("doesntexist_csv_tab_vertbar", "doesntexist", out)
        self.validate_one("onemore_csv_tab_vertbar", "onemore", out)
        self.validate_one("complex_csv_tab_vertbar", "cömplex", out)
        self.validate_one("jamie_csv_tab_vertbar", "jãmïe", out)

    @unittest.skipIf(lib.platform == "Windows",
                     "Windows DLL isn't backwards compatible")
    def test_firefox_20_default(self):
        test = os.path.join(self.test, "test_profile_firefox_20")

        cmd = lib.get_script() + [test, "--format", "csv"]
        output = lib.run(cmd, stdin=self.pwd)
        self.validate_default(output)

    @unittest.skipIf(lib.platform == "Windows",
                     "Windows DLL isn't backwards compatible")
    def test_firefox_20_tabular(self):
        test = os.path.join(self.test, "test_profile_firefox_20")

        cmd = lib.get_script() + [test, "--format", "tabular"]
        output = lib.run(cmd, stdin=self.pwd)
        self.validate_tabular(output)

    @unittest.skipIf(lib.platform == "Windows",
                     "Windows DLL isn't backwards compatible")
    def test_firefox_20_semicol(self):
        test = os.path.join(self.test, "test_profile_firefox_20")

        cmd = lib.get_script() + [test, "--format", "csv", "--csv-delimiter", ";", "--csv-quotechar", "'"]
        output = lib.run(cmd, stdin=self.pwd)
        self.validate_semicol(output)

    @unittest.skipIf(lib.platform == "Windows",
                     "Windows DLL isn't backwards compatible")
    def test_firefox_20_vertbar(self):
        test = os.path.join(self.test, "test_profile_firefox_20")

        cmd = lib.get_script() + [test, "--format", "csv", "--csv-delimiter", "\t", "--csv-quotechar", "|"]
        output = lib.run(cmd, stdin=self.pwd)
        self.validate_vertbar(output)

    @unittest.skipIf(lib.platform == "Windows",
                     "Windows DLL isn't backwards compatible")
    def test_firefox_46_default(self):
        test = os.path.join(self.test, "test_profile_firefox_46")

        cmd = lib.get_script() + [test, "--format", "csv"]
        output = lib.run(cmd, stdin=self.pwd)
        self.validate_default(output)

    @unittest.skipIf(lib.platform == "Windows",
                     "Windows DLL isn't backwards compatible")
    def test_firefox_46_tabular(self):
        test = os.path.join(self.test, "test_profile_firefox_46")

        cmd = lib.get_script() + [test, "--format", "tabular"]
        output = lib.run(cmd, stdin=self.pwd)
        self.validate_tabular(output)

    @unittest.skipIf(lib.platform == "Windows",
                     "Windows DLL isn't backwards compatible")
    def test_firefox_46_semicol(self):
        test = os.path.join(self.test, "test_profile_firefox_46")

        cmd = lib.get_script() + [test, "--format", "csv", "--csv-delimiter", ";", "--csv-quotechar", "'"]
        output = lib.run(cmd, stdin=self.pwd)
        self.validate_semicol(output)

    @unittest.skipIf(lib.platform == "Windows",
                     "Windows DLL isn't backwards compatible")
    def test_firefox_46_vertbar(self):
        test = os.path.join(self.test, "test_profile_firefox_46")

        cmd = lib.get_script() + [test, "--format", "csv", "--csv-delimiter", "\t", "--csv-quotechar", "|"]
        output = lib.run(cmd, stdin=self.pwd)
        self.validate_vertbar(output)

    def test_firefox_59_default(self):
        test = os.path.join(self.test, "test_profile_firefox_59")

        cmd = lib.get_script() + [test, "--format", "csv"]
        output = lib.run(cmd, stdin=self.pwd)
        self.validate_default(output)

    def test_firefox_59_tabular(self):
        test = os.path.join(self.test, "test_profile_firefox_59")

        cmd = lib.get_script() + [test, "--format", "tabular"]
        output = lib.run(cmd, stdin=self.pwd)
        self.validate_tabular(output)

    def test_firefox_59_semicol(self):
        test = os.path.join(self.test, "test_profile_firefox_59")

        cmd = lib.get_script() + [test, "--format", "csv", "--csv-delimiter", ";", "--csv-quotechar", "'"]
        output = lib.run(cmd, stdin=self.pwd)
        self.validate_semicol(output)

    def test_firefox_59_vertbar(self):
        test = os.path.join(self.test, "test_profile_firefox_59")

        cmd = lib.get_script() + [test, "--format", "csv", "--csv-delimiter", "\t", "--csv-quotechar", "|"]
        output = lib.run(cmd, stdin=self.pwd)
        self.validate_vertbar(output)

    @unittest.skipIf(lib.platform == "Windows",
                     "Windows DLL isn't backwards compatible")
    def test_firefox_nopassword_46_default(self):
        test = os.path.join(self.test, "test_profile_firefox_nopassword_46")

        cmd = lib.get_script() + [test, "-n", "--format", "csv"]
        output = lib.run(cmd)
        self.validate_default(output)

    @unittest.skipIf(lib.platform == "Windows",
                     "Windows DLL isn't backwards compatible")
    def test_firefox_nopassword_46_tabular(self):
        test = os.path.join(self.test, "test_profile_firefox_nopassword_46")

        cmd = lib.get_script() + [test, "-n", "--format", "tabular"]
        output = lib.run(cmd)
        self.validate_tabular(output)

    @unittest.skipIf(lib.platform == "Windows",
                     "Windows DLL isn't backwards compatible")
    def test_firefox_nopassword_46_semicol(self):
        test = os.path.join(self.test, "test_profile_firefox_nopassword_46")

        cmd = lib.get_script() + [test, "-n", "--format", "csv", "--csv-delimiter", ";", "--csv-quotechar", "'"]
        output = lib.run(cmd)
        self.validate_semicol(output)

    @unittest.skipIf(lib.platform == "Windows",
                     "Windows DLL isn't backwards compatible")
    def test_firefox_nopassword_46_vertbar(self):
        test = os.path.join(self.test, "test_profile_firefox_nopassword_46")

        cmd = lib.get_script() + [test, "-n", "--format", "csv", "--csv-delimiter", "\t", "--csv-quotechar", "|"]
        output = lib.run(cmd)
        self.validate_vertbar(output)

    def test_firefox_nopassword_59_default(self):
        test = os.path.join(self.test, "test_profile_firefox_nopassword_59")

        cmd = lib.get_script() + [test, "-n", "--format", "csv"]
        output = lib.run(cmd)
        self.validate_default(output)

    def test_firefox_nopassword_59_tabular(self):
        test = os.path.join(self.test, "test_profile_firefox_nopassword_59")

        cmd = lib.get_script() + [test, "-n", "--format", "tabular"]
        output = lib.run(cmd)
        self.validate_tabular(output)

    def test_firefox_nopassword_59_semicol(self):
        test = os.path.join(self.test, "test_profile_firefox_nopassword_59")

        cmd = lib.get_script() + [test, "-n", "--format", "csv", "--csv-delimiter", ";", "--csv-quotechar", "'"]
        output = lib.run(cmd)
        self.validate_semicol(output)

    def test_firefox_nopassword_59_vertbar(self):
        test = os.path.join(self.test, "test_profile_firefox_nopassword_59")

        cmd = lib.get_script() + [test, "-n", "--format", "csv", "--csv-delimiter", "\t", "--csv-quotechar", "|"]
        output = lib.run(cmd)
        self.validate_vertbar(output)


if __name__ == "__main__":
    from simpletap import TAPTestRunner
    unittest.main(testRunner=TAPTestRunner(buffer=True), exit=False)

# vim: ai sts=4 et sw=4

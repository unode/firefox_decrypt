#!/usr/bin/env python3

import unittest
import os
import shutil
import contextlib
import copy
import json
import tempfile
import subprocess
from simpletap.fdecrypt import lib


class TestImport(unittest.TestCase):
    def setUp(self):
        self.test = lib.get_test_data()
        self.pwd = lib.get_password()

    @contextlib.contextmanager
    def prepare_temp_profile(self, dirname):
        sourcedir = os.path.join(self.test, dirname)
        targetdir = tempfile.mkdtemp()
        os.rmdir(targetdir)
        shutil.copytree(sourcedir, targetdir)

        try:
            yield targetdir

        finally:
            shutil.rmtree(targetdir, ignore_errors=True)

    class ImportContext:
        def __init__(self, original_content):
            self.original_content = original_content
            self.changed_content = copy.deepcopy(original_content)
            self.changed_entries = []

        def change_entries(self, *patterns):
            for old_entry, new_entry in zip(self.original_content, self.changed_content):
                for pattern in patterns:
                    if pattern in old_entry['user']:
                        yield new_entry
                        if old_entry != new_entry:
                            self.changed_entries.append(new_entry)

                        break

    @contextlib.contextmanager
    def validate_profile_change(self, dirname, password=None):
        with self.prepare_temp_profile(dirname) as trgdir:
            command_begin = lib.get_script() + [trgdir]

            if password is None:
                stdin = None
                command_begin += ['-n']

            else:
                stdin = password

            cmd = command_begin + ["--format", "json"]
            output = lib.run(cmd, stdin=stdin, stderr=subprocess.DEVNULL)
            orig_data = list(sorted(json.loads(output), key=lambda entry: entry['user']))

            import_context = self.ImportContext(orig_data)
            yield import_context

            dest_json = os.path.join(trgdir, "import.json")
            with open(dest_json, 'wt') as fd:
                json.dump(import_context.changed_entries, fd)

            cmd = command_begin + ["--format", "json", "--update", dest_json]
            lib.run(cmd, stdin=stdin, stderr=subprocess.DEVNULL)

            cmd = command_begin + ["--format", "json"]
            new_output = lib.run(cmd, stdin=stdin, stderr=subprocess.DEVNULL)
            new_data = list(sorted(json.loads(output), key=lambda entry: entry['user']))

            self.assertEqual(new_data, orig_data)

    def validate_reversed_password(self, dirname, patterns, password=None):
        with self.validate_profile_change(dirname, password) as context:
            for entry in context.change_entries(*patterns):
                entry['password'] = ''.join(reversed(entry['password']))

    def test_firefox_20_default(self):
        self.validate_reversed_password("test_profile_firefox_20",
                [ "doesntexist" ], password=self.pwd)
        self.validate_reversed_password("test_profile_firefox_20",
                [ "onemore" ], password=self.pwd)
        self.validate_reversed_password("test_profile_firefox_20",
                [ "cömplex" ], password=self.pwd)
        self.validate_reversed_password("test_profile_firefox_20",
                [ "jãmïe" ] , password=self.pwd)
        self.validate_reversed_password("test_profile_firefox_20",
                [ "doesntexist", "onemore", "cömplex", "jãmïe" ], password=self.pwd)

    def test_firefox_46_default(self):
        self.validate_reversed_password("test_profile_firefox_46",
                [ "doesntexist" ], password=self.pwd)
        self.validate_reversed_password("test_profile_firefox_46",
                [ "onemore" ], password=self.pwd)
        self.validate_reversed_password("test_profile_firefox_46",
                [ "cömplex" ], password=self.pwd)
        self.validate_reversed_password("test_profile_firefox_46",
                [ "jãmïe" ] , password=self.pwd)
        self.validate_reversed_password("test_profile_firefox_46",
                [ "doesntexist", "onemore", "cömplex", "jãmïe" ], password=self.pwd)

    def test_firefox_59_default(self):
        self.validate_reversed_password("test_profile_firefox_59",
                [ "doesntexist" ], password=self.pwd)
        self.validate_reversed_password("test_profile_firefox_59",
                [ "onemore" ], password=self.pwd)
        self.validate_reversed_password("test_profile_firefox_59",
                [ "cömplex" ], password=self.pwd)
        self.validate_reversed_password("test_profile_firefox_59",
                [ "jãmïe" ] , password=self.pwd)
        self.validate_reversed_password("test_profile_firefox_59",
                [ "doesntexist", "onemore", "cömplex", "jãmïe" ], password=self.pwd)

    def test_firefox_nopassword_default(self):
        self.validate_reversed_password("test_profile_firefox_nopassword",
                [ "doesntexist" ])
        self.validate_reversed_password("test_profile_firefox_nopassword",
                [ "onemore" ])
        self.validate_reversed_password("test_profile_firefox_nopassword",
                [ "cömplex" ])
        self.validate_reversed_password("test_profile_firefox_nopassword",
                [ "jãmïe" ] )
        self.validate_reversed_password("test_profile_firefox_nopassword",
                [ "doesntexist", "onemore", "cömplex", "jãmïe" ])


if __name__ == "__main__":
    from simpletap import TAPTestRunner
    unittest.main(testRunner=TAPTestRunner())

# vim: ai sts=4 et sw=4

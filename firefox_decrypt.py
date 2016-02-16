#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Disclamer: Parts of this script were taken from the great tool:
# dumpzilla at www.dumpzilla.org

import sys
from sys import stdout as out
from sys import stderr as err
import os
import sqlite3
import json
import argparse
from base64 import b64decode
from os import path
from ctypes import c_uint, c_void_p, c_char_p, cast, byref, string_at
from ctypes import Structure, CDLL
from getpass import getpass

try:
    # Python 3
    from configparser import ConfigParser
    raw_input = input
except ImportError:
    # Python 2
    from ConfigParser import ConfigParser

VERBOSE = False
NSS = None


class NotFoundError(Exception):
    pass


class Exit(Exception):
    def __init__(self, exitcode):
        self.exitcode = exitcode

    def __unicode__(self):
        return "Premature program exit with exit code {0}".format(self.exitcode)


class Item(Structure):
    _fields_ = [('type', c_uint), ('data', c_void_p), ('len', c_uint)]


class Credentials(object):
    def __init__(self, db):
        self.db = db

        if not path.isfile(db):
            raise NotFoundError("ERROR - {0} database not found\n".format(db))

        err.write("Info - Using {0} for credentials.\n".format(db))

    def __iter__(self):
        pass

    def done(self):
        pass


class SqliteCredentials(Credentials):
    def __init__(self, profile):
        db = profile + "/signons.sqlite"

        super(SqliteCredentials, self).__init__(db)

        self.conn = sqlite3.connect(db)
        self.c = self.conn.cursor()

    def __iter__(self):
        self.c.execute("SELECT hostname, encryptedUsername, encryptedPassword, encType "
                       "FROM moz_logins")
        for i in self.c:
            # yields hostname, encryptedUsername, encryptedPassword, encType
            yield i

    def done(self):
        super(SqliteCredentials, self).done()

        self.c.close()
        self.conn.close()


class JsonCredentials(Credentials):
    def __init__(self, profile):
        db = profile + "/logins.json"

        super(JsonCredentials, self).__init__(db)

    def __iter__(self):
        with open(self.db) as fh:
            data = json.load(fh)

            try:
                logins = data["logins"]
            except:
                raise Exception("Unrecognized format in {0}".format(self.db))

            for i in logins:
                # yields hostname, encryptedUsername, encryptedPassword
                yield (i["hostname"], i["encryptedUsername"],
                       i["encryptedPassword"], i["encType"])


def handle_error():
    """If an error happens in libnss, handle it and print some debug information
    """
    error = NSS.PORT_GetError()
    NSS.PR_ErrorToString.restype = c_char_p
    NSS.PR_ErrorToName.restype = c_char_p
    error_str = NSS.PR_ErrorToString(error)
    error_name = NSS.PR_ErrorToName(error)
    err.write("[DEBUG] {0}: {1}\n".format(error_name, error_str))


def decrypt_passwords(profile, password):
    """
    Decrypt requested profile using the provided password and print out all
    stored passwords.
    """

    if NSS.NSS_Init(profile.encode("utf8")) != 0:
        err.write("ERROR - Couldn't initialize NSS\n")
        handle_error()
        raise Exit(5)

    if password:
        password = c_char_p(password.encode("utf8"))
        keyslot = NSS.PK11_GetInternalKeySlot()
        if keyslot is None:
            err.write("ERROR - Failed to retrieve internal KeySlot\n")
            handle_error()
            raise Exit(6)

        if NSS.PK11_CheckUserPassword(keyslot, password) != 0:
            err.write("ERROR - Master password is not correct\n")
            handle_error()
            raise Exit(7)
    else:
        err.write("Warning - Attempting decryption with no Master Password\n")

    username = Item()
    passwd = Item()
    outuser = Item()
    outpass = Item()

    # Any password in this profile store at all?
    got_password = False

    try:
        credentials = JsonCredentials(profile)
    except NotFoundError:
        try:
            credentials = SqliteCredentials(profile)
        except NotFoundError:
            err.write("ERROR - Couldn't find credentials file "
                      "(logins.json or signons.sqlite).\n")
            raise Exit(4)

    for host, user, passw, enctype in credentials:
        got_password = True

        if enctype:
            username.data = cast(c_char_p(b64decode(user)), c_void_p)
            username.len = len(b64decode(user))
            passwd.data = cast(c_char_p(b64decode(passw)), c_void_p)
            passwd.len = len(b64decode(passw))

            if NSS.PK11SDR_Decrypt(byref(username), byref(outuser), None) == -1:
                err.write("ERROR - Passwords protected by a Master Password!\n")
                handle_error()
                raise Exit(8)

            if NSS.PK11SDR_Decrypt(byref(passwd), byref(outpass), None) == -1:
                # This shouldn't really happen but failsafe just in case
                err.write("ERROR - Given Master Password is not correct!\n")
                handle_error()
                raise Exit(9)

            user = string_at(outuser.data, outuser.len)
            passw = string_at(outpass.data, outpass.len)

        if sys.version_info[0] > 2:
            user = user.decode("utf8")
            passw = passw.decode("utf8")

        out.write("Website:   {0}\n".format(host))
        out.write("Username: '{0}'\n".format(user))
        out.write("Password: '{0}'\n\n".format(passw))

    credentials.done()
    NSS.NSS_Shutdown()

    if not got_password:
        err.write("Warning - No passwords found in selected profile\n")


def ask_section(profiles):
    """
    Prompt the user which profile should be used for decryption
    """
    sections = {}
    i = 1
    for section in profiles.sections():
        if section.startswith("Profile"):
            sections[str(i)] = profiles.get(section, "Path")
        else:
            continue
        i += 1

    choice = None
    while choice not in sections:
        err.write("Select the Firefox profile you wish to decrypt\n")
        for i in sorted(sections):
            err.write("{0} -> {1}\n".format(i, sections[i]))
        err.flush()
        choice = raw_input("Choice: ")

    return sections[choice]


def ask_password(profile):
    """
    Prompt for profile password
    """
    utf8 = "UTF-8"
    input_encoding = utf8 if sys.stdin.encoding in (None, 'ascii') else sys.stdin.encoding
    passmsg = "\nMaster Password for profile {}: ".format(profile)

    if sys.stdin.isatty():
        passwd = getpass(passmsg)

    else:
        # Ability to read the password from stdin (echo "pass" | ./firefox_...)
        passwd = sys.stdin.readline().rstrip("\n")

    if sys.version_info[0] > 2:
        return passwd
    else:
        return passwd.decode(input_encoding)


def parse_sys_args():
    profile_path = "~/.mozilla/firefox/"

    parser = argparse.ArgumentParser(
        description="Access Firefox profiles and decrypt existing passwords"
    )
    parser.add_argument("profile", nargs='?', default=profile_path,
                        help="Path to profile folder (default: {0})".format(profile_path))
    parser.add_argument("-v", "--verbose", action="store_true", default=False,
                        help="Enable debugging/verbose output")

    args = parser.parse_args()

    if args.verbose:
        global VERBOSE
        VERBOSE = True

    return args


def load_libnss():
    firefox = ""

    if os.name == "nt":
        nssname = "nss3.dll"
        firefox = r"c:\Program Files (x86)\Mozilla Firefox"
        os.environ["PATH"] = ';'.join([os.environ["PATH"], firefox])

    else:
        nssname = "libnss3.so"

    try:
        global NSS
        NSS = CDLL(os.path.join(firefox, nssname))

    except Exception as e:
        err.write("Problems opening '{0}' required for password "
                  "decryption\n".format(nssname))
        err.write("Error was {0}\n".format(e))
        raise Exit(3)


def read_profiles(basepath):
    profileini = os.path.join(basepath, "profiles.ini")

    if not os.path.isfile(profileini):
        err.write("ERROR: profile.ini not found in {0}, "
                  "please provide the correct path\n".format(basepath))
        raise Exit(2)

    # Read profiles from Firefox profile folder
    profiles = ConfigParser()
    profiles.read(profileini)

    return profiles


def main():
    args = parse_sys_args()

    load_libnss()

    basepath = path.expanduser(args.profile)

    # Read profiles from profiles.ini in profile folder
    profiles = read_profiles(basepath)

    # Ask user which profile want's to open
    section = ask_section(profiles)

    # Prompt for Master Password
    profile = os.path.join(basepath, section)
    password = ask_password(profile)

    # And finally decode all passwords
    decrypt_passwords(profile, password)


if __name__ == "__main__":
    try:
        main()
    except Exit as e:
        sys.exit(e.exitcode)

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
from ConfigParser import ConfigParser
from base64 import b64decode
from os import path
from ctypes import c_uint, c_void_p, c_char_p, cast, byref, string_at
from ctypes import Structure, CDLL
from getpass import getpass


class NotFoundError(Exception):
    pass


class Item(Structure):
    _fields_ = [('type', c_uint), ('data', c_void_p), ('len', c_uint)]


class Credentials(object):
    def __init__(self, db):
        self.db = db

        if not path.isfile(db):
            raise NotFoundError("Error - {0} database not found\n".format(db))

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
        self.c.execute("SELECT hostname, encryptedUsername, encryptedPassword "
                       "FROM moz_logins")
        for i in self.c:
            # yields hostname, encryptedUsername, encryptedPassword
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
                       i["encryptedPassword"])


def decrypt_passwords(profile, password):
    """
    Decrypt requested profile using the provided password and print out all
    stored passwords.
    """

    if libnss.NSS_Init(profile) != 0:
        err.write("Error - Couldn't initialize NSS\n")
        return 5

    if password:
        password = c_char_p(password)
        keyslot = libnss.PK11_GetInternalKeySlot()
        if keyslot is None:
            err.write("Error - Failed to retrieve internal KeySlot\n")
            return 6

        if libnss.PK11_CheckUserPassword(keyslot, password) != 0:
            err.write("Error - Master password is not correct\n")
            return 7
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
            err.write("Error - Couldn't find credentials file "
                      "(logins.json or signons.sqlite).\n")
            return 4

    for host, user, passw in credentials:
        got_password = True
        username.data = cast(c_char_p(b64decode(user)), c_void_p)
        username.len = len(b64decode(user))
        passwd.data = cast(c_char_p(b64decode(passw)), c_void_p)
        passwd.len = len(b64decode(passw))

        if libnss.PK11SDR_Decrypt(byref(username), byref(outuser), None) == -1:
            err.write("Error - Passwords protected by a Master Password!\n")
            return 8

        if libnss.PK11SDR_Decrypt(byref(passwd), byref(outpass), None) == -1:
            # This shouldn't really happen but failsafe just in case
            err.write("Error - Given Master Password is not correct!\n")
            return 9

        out.write("Website:   {0}\n".format(host.encode("utf-8")))
        out.write("Username: '{0}'\n".format(string_at(outuser.data,
                                                       outuser.len)))
        out.write("Password: '{0}'\n\n".format(string_at(outpass.data,
                                                         outpass.len)))

    credentials.done()
    libnss.NSS_Shutdown()

    if not got_password:
        err.write("Warning - No passwords found in selected profile\n")

    return 0


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
    passmsg = "\nMaster Password for profile {}: ".format(profile)
    return getpass(passmsg)


def main():
    profile_path = "~/.mozilla/firefox/"

    if len(sys.argv) > 2:
        err.write("Usage: python {0} [profile_location]\n".format(sys.argv[0]))
        err.write("   ... profile_location defaults to {0}\n".format(
            profile_path))
        sys.exit(1)
    elif len(sys.argv) == 2:
        profile_path = sys.argv[-1]

    basepath = path.expanduser(profile_path)
    profileini = os.path.join(basepath, "profiles.ini")

    if not os.path.isfile(profileini):
        err.write("ERROR: profile.ini not found in {0}, "
            "please provide the correct path\n".format(basepath))
        sys.exit(2)

    # Read profiles from Firefox profile folder
    profiles = ConfigParser()
    profiles.read(profileini)

    # Ask user which profile want's to open
    section = ask_section(profiles)

    # Prompt for Master Password
    profile = os.path.join(basepath, section)
    password = ask_password(profile)

    # And finally decode all passwords
    out = decrypt_passwords(profile, password)

    sys.exit(out)

if __name__ == "__main__":
    try:
        libnss = CDLL("libnss3.so")
    except Exception as e:
        err.write("Problems opening 'libnss3.so' required for password "
            "decryption\n")
        err.write("Error was {0}\n".format(e))
        sys.exit(3)

    main()

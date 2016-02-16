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
import logging
from base64 import b64decode
from os import path
from ctypes import c_uint, c_void_p, c_char_p, cast, byref, string_at
from ctypes import Structure, CDLL
from getpass import getpass
LOG = None

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

        LOG.debug("Database location: %s", self.db)
        if not path.isfile(db):
            raise NotFoundError("ERROR - {0} database not found\n".format(db))

        LOG.info("Using %s for credentials.", db)

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
        LOG.debug("Reading password database in SQLite format")
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
            LOG.debug("Reading password database in JSON format")
            data = json.load(fh)

            try:
                logins = data["logins"]
            except:
                raise Exception("Unrecognized format in {0}".format(self.db))

            for i in logins:
                yield (i["hostname"], i["encryptedUsername"],
                       i["encryptedPassword"], i["encType"])


def handle_error():
    """If an error happens in libnss, handle it and print some debug information
    """
    LOG.debug("Error during a call to NSS library, trying to obtain error info")

    error = NSS.PORT_GetError()
    NSS.PR_ErrorToString.restype = c_char_p
    NSS.PR_ErrorToName.restype = c_char_p
    error_str = NSS.PR_ErrorToString(error)
    error_name = NSS.PR_ErrorToName(error)

    if sys.version_info[0] > 2:
        error_name = error_name.decode("utf8")
        error_str = error_str.decode("utf8")

    LOG.debug("%s: %s", error_name, error_str)


def decrypt_passwords(profile, password):
    """
    Decrypt requested profile using the provided password and print out all
    stored passwords.
    """

    LOG.debug("Initializing NSS with profile path '%s'", profile)

    i = NSS.NSS_Init(profile.encode("utf8"))
    LOG.debug("Initializing NSS returned %s", i)

    if i != 0:
        LOG.error("Couldn't initialize NSS")
        handle_error()
        raise Exit(5)

    if password:
        LOG.debug("Retrieving internal key slot")
        p_password = c_char_p(password.encode("utf8"))
        keyslot = NSS.PK11_GetInternalKeySlot()
        LOG.debug("Internal key slot %s", keyslot)

        if keyslot is None:
            LOG.error("Failed to retrieve internal KeySlot")
            handle_error()
            raise Exit(6)

        LOG.debug("Authenticating with password '%s'", password)

        i = NSS.PK11_CheckUserPassword(keyslot, p_password)
        LOG.debug("Checking user password returned %s", i)

        if i != 0:
            LOG.error("Master password is not correct")
            handle_error()
            raise Exit(7)
    else:
        LOG.warn("Attempting decryption with no Master Password")

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
            LOG.error("Couldn't find credentials file (logins.json or signons.sqlite).")
            raise Exit(4)

    for host, user, passw, enctype in credentials:
        got_password = True

        if enctype:
            username.data = cast(c_char_p(b64decode(user)), c_void_p)
            username.len = len(b64decode(user))
            passwd.data = cast(c_char_p(b64decode(passw)), c_void_p)
            passwd.len = len(b64decode(passw))

            LOG.debug("Decrypting username data '%s'", user)

            i = NSS.PK11SDR_Decrypt(byref(username), byref(outuser), None)
            LOG.debug("Decryption of username returned %s", i)

            if i == -1:
                LOG.error("Passwords protected by a Master Password!")
                handle_error()
                raise Exit(8)

            LOG.debug("Decrypting password data '%s'", passwd)

            i = NSS.PK11SDR_Decrypt(byref(passwd), byref(outpass), None)
            LOG.debug("Decryption of password returned %s", i)

            if i == -1:
                # This shouldn't really happen but failsafe just in case
                LOG.error("Given Master Password is not correct!")
                handle_error()
                raise Exit(9)

            user = string_at(outuser.data, outuser.len)
            passw = string_at(outpass.data, outpass.len)

        if sys.version_info[0] > 2:
            LOG.debug("Decoding username '%s' and password '%s' for website '%s'", user, passw, host)
            user = user.decode("utf8")
            passw = passw.decode("utf8")

        out.write("Website:   {0}\n".format(host))
        out.write("Username: '{0}'\n".format(user))
        out.write("Password: '{0}'\n\n".format(passw))

    credentials.done()
    NSS.NSS_Shutdown()

    if not got_password:
        LOG.warn("No passwords found in selected profile")


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

    final_choice = sections[choice]
    LOG.debug("Profile selection matched %s", final_choice)

    return final_choice


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
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Verbosity level. Warning on -vv (highest level) user input will be printed on screen")

    args = parser.parse_args()

    return args


def load_libnss():
    firefox = ""

    if os.name == "nt":
        nssname = "nss3.dll"
        firefox = r"c:\Program Files (x86)\Mozilla Firefox"
        os.environ["PATH"] = ';'.join([os.environ["PATH"], firefox])
        LOG.debug("PATH is now %s", os.environ["PATH"])

    else:
        nssname = "libnss3.so"

    try:
        nsslib = os.path.join(firefox, nssname)
        LOG.debug("Loading NSS library from %s", nsslib)

        global NSS
        NSS = CDLL(nsslib)

    except Exception as e:
        LOG.error("Problems opening '%s' required for password decryption", nssname)
        LOG.error("Error was %s", e)
        raise Exit(3)


def read_profiles(basepath):
    profileini = os.path.join(basepath, "profiles.ini")

    LOG.debug("Reading profiles from %s", profileini)

    if not os.path.isfile(profileini):
        LOG.error("profile.ini not found in %s, please provide the correct path", basepath)
        raise Exit(2)

    # Read profiles from Firefox profile folder
    profiles = ConfigParser()
    profiles.read(profileini)

    LOG.debug("Read profiles %s", profiles.sections())

    return profiles


def setup_logging(args):
    if args.verbose == 1:
        level = logging.INFO
    elif args.verbose >= 2:
        level = logging.DEBUG
    else:
        level = logging.WARN

    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=level,
    )

    global LOG
    LOG = logging.getLogger(__name__)


def main():
    args = parse_sys_args()

    setup_logging(args)

    LOG.debug("Parsed commandline arguments: %s", args)

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

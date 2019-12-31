### Firefox Decrypt

[![Build Status](https://travis-ci.org/unode/firefox_decrypt.svg?branch=master)](https://travis-ci.org/unode/firefox_decrypt) [![wercker status](https://app.wercker.com/status/d9b714c5d195dd9e7582e8cd6f463982/m/master "wercker status")](https://app.wercker.com/project/byKey/d9b714c5d195dd9e7582e8cd6f463982)

**The master branch is unstable during migration to Python 3.**  

If you must use Python 2, please try [Firefox Decrypt 0.7.0](https://github.com/unode/firefox_decrypt/releases/tag/0.7.0).  

If you encounter a problem, try the latest [release](https://github.com/unode/firefox_decrypt/releases) or check open issues for ongoing work.

#### About

**Firefox Decrypt** is a tool to extract passwords from profiles of Mozilla (Fire/Water)fox™, Thunderbird®, SeaMonkey® and some derivates.

It can be used to recover passwords from a profile protected by a Master Password as long as the latter is known.
If a profile is not protected by a Master Password, a password will still be requested but can be left blank.

This tool does not try to crack or brute-force the Master Password in any way.
If the Master Password is not known it will simply fail to recover any data.

This script is written in Python and is compatible with versions ~~2.7+~~ (last is [0.7.0](https://github.com/unode/firefox_decrypt/releases/tag/0.7.0)) and 3.6+. On Windows, only Python 3 is supported.

Additionally, it requires access to libnss3 which is included with Firefox and
Thunderbird, although depending on system configuration, the script may fail to
locate the library or may load an incorrect/incompatible version.

Alternatively, you can install libnss3 (Debian/Ubuntu) or nss (Arch/Gentoo/…).
libnss3 is part of https://developer.mozilla.org/docs/Mozilla/Projects/NSS

If you need to decode passwords from Firefox 3 or older, this is not officially supported but a patch exists in [this pull request](https://github.com/unode/firefox_decrypt/pull/36).


#### Usage

Run:

```
python firefox_decrypt.py
```

The tool will present a numbered list of profiles. Enter the relevant number. 

Then, a prompt to enter the *master password* for the profile: 

- if no password was set, enter nothing – simply key <kbd>Return</kbd> or <kbd>Enter</kbd>
- if a password was set and is known, enter it
- if a password was set and is no longer known, you can not proceed

#### Advanced usage

If your profiles are at an unusual path, you can call the script with:

```
python firefox_decrypt.py /folder/containing/profiles.ini/
```

If you don't want to display all passwords on the screen you can use:

```
python firefox_decrypt.py | grep -C2 keyword
```
where `keyword` is part of the expected output (URL, username, email, password …)

Since version **0.7.0** passwords may be exported in CSV format using the `--format` flag.

```
python firefox_decrypt.py --format csv
```

Additionally, `--delimiter` and `--quotechar` flags can specify which characters to use as delimiters and quote characters in the CSV output.

Since version **0.4** it is possible to export stored passwords to *pass* from <http://passwordstore.org/>. To do so, use:

```
python firefox_decrypt.py --export-pass
```

and **all** existing passwords will be exported after the pattern `web/<address>[:<port>]` unless multiple credentials exist for the same website in which case `/<login>` is appended. The username will be on a second line.

To prefix the username with `login: ` for compatibility with the [browserpass](https://github.com/dannyvankooten/browserpass) extension, you can use:
```
python firefox_decrypt.py --export-pass --pass-compat browserpass
```

There is currently no way to selectively export passwords.

Exporting will overwrite existing passwords without warning. Ensure you have a backup or are using the `pass git` functionality.

Starting with version **0.5.2** it is now possible to use a non-interactive mode which bypasses all prompts, including profile choice and master password. Use it with `-n/--no-interactive`. Indicate your profile choice by passing `-c/--choice N` where N is the number of the profile you wish to decrypt (starting from **1**).

You can list all available profiles with `-l/--list` (to stdout).

Your master password is read from stdin.

    $ python firefox_decrypt.py --list
    1 -> l1u1xh65.default
    2 -> vuhdnx5b.YouTube
    3 -> 1d8vcool.newdefault
    4 -> ekof2ces.SEdu
    5 -> 8a52xmtt.Fresh

    $ read -sp "Master Password: " PASSWORD
    Master Password:

    $ echo $PASSWORD | python firefox_decrypt.py --no-interactive --choice 4
    Website:   https://login.example.com
    Username: 'john.doe'
    Password: '1n53cur3'

    Website:   https://example.org
    Username: 'max.mustermann'
    Password: 'Passwort1234'

    Website:   https://github.com
    Username: 'octocat'
    Password: 'qJZo6FduRcHw'

    [...snip...]

    $ echo $PASSWORD | python firefox_decrypt.py -nc 1
    Website:   https://git-scm.com
    Username: 'foo'
    Password: 'bar'

    Website:   https://gitlab.com
    Username: 'whatdoesthefoxsay'
    Password: 'w00fw00f'

    [...snip...]

    $ # Unset Password
    $ PASSWORD=

#### Troubleshooting

If a problem occurs, please try `firefox_decrypt` in high verbosity mode by calling it with:

```
python firefox_decrypt.py -vvv
```

If the output does not help you to identify the cause and a solution to the problem, file a bug report including the verbose output. **Beware**:  

- your profile password, as well as other passwords, may be visible in the output – so **please remove any sensitive data** before sharing the output.


##### Windows

Both Python and Firefox must be either 32-bit or 64-bit.  

If you mix architectures the code will fail. More information on issue [#8](https://github.com/unode/firefox_decrypt/issues/8).

##### Darwin/macOS

If you get the error described in [#14](https://github.com/unode/firefox_decrypt/issues/14) when loading `libnss3`, consider installing `nss` using brew or an alternative package manager.

#### Testing

If you wish to run the test suite locally, chdir into `tests/` and run `./run_all`

If any test fails on your system, please ensure `libnss` is installed.

If tests continue to fail, re-run with `./run_all -v` then please file a bug report including: 

- the output
- information about your system (e.g. Linux distribution, version of libnss/firefox …). 

It is much appreciated.

### Spin-off, derived and related works

* [firepwned](https://github.com/christophetd/firepwned#how-it-works) - check if your passwords have been involved in a known data leak
* [FF Password Exporter](https://github.com/kspearrin/ff-password-exporter) - Firefox AddOn for exporting passwords. 

----

Firefox is a trademark of the Mozilla Foundation in the U.S. and other countries.

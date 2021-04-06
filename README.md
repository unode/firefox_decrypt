### Firefox Decrypt

![GitHub Actions status](https://github.com/unode/firefox_decrypt/actions/workflows/main.yml/badge.svg)

As of 1.0.0-rc1 Python 3.9+ is required. Python 2 is no longer supported.
If you encounter a problem, try the latest [release](https://github.com/unode/firefox_decrypt/releases) or check open issues for ongoing work.

If you definitely need to use Python 2, [Firefox Decrypt 0.7.0](https://github.com/unode/firefox_decrypt/releases/tag/0.7.0) is your best bet, although no longer supported.

#### About

**Firefox Decrypt** is a tool to extract passwords from profiles of Mozilla (Fire/Water)fox™, Thunderbird®, SeaMonkey® and derivates.

It can be used to recover passwords from a profile protected by a Master Password as long as the latter is known.
If a profile is not protected by a Master Password, passwords are displayed without prompt.

This tool does not try to crack or brute-force the Master Password in any way.
If the Master Password is not known it will simply fail to recover any data.

It requires access to libnss3, included with most Mozilla products.
The script is usually able to find a compatible library but may in some cases
load an incorrect/incompatible version. If you encounter this situation please file a bug report.

Alternatively, you can install libnss3 (Debian/Ubuntu) or nss (Arch/Gentoo/…).
libnss3 is part of https://developer.mozilla.org/docs/Mozilla/Projects/NSS

If you need to decode passwords from Firefox 3 or older, although not officially supported,
there is a patch in [this pull request](https://github.com/unode/firefox_decrypt/pull/36).


#### Usage

Run:

```
python firefox_decrypt.py
```

The tool will present a numbered list of profiles. Enter the relevant number. 

Then, a prompt to enter the *master password* for the profile: 

- if no password was set, no master password will be asked.
- if a password was set and is known, enter it and hit key <kbd>Return</kbd> or <kbd>Enter</kbd>
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

You can also choose from one of the supported formats with `--format`:

* `human` - a format displaying one record for every 3 lines
* `csv` - a spreadsheet-like format. See also `--csv-*` options for additional control.
* `tabular` - similar to csv but producing a tab-delimited (`tsv`) file instead.
* `json` - a machine compatible format - see [JSON](https://en.wikipedia.org/wiki/JSON)
* `pass` - a special output format that directly calls to the [passwordstore.org](https://www.passwordstore.org) command to export passwords (*). See also `--pass-*` options.

(*) `pass` can produce unintended consequences. Make sure to backup your password store before using this.

##### Format CSV

Passwords may be exported in CSV format using the `--format` flag.

```
python firefox_decrypt.py --format csv
```

Additionally, `--csv-delimiter` and `--csv-quotechar` flags can specify which characters to use as delimiters and quote characters in the CSV output.

##### Format Pass - Passwordstore

Stored passwords can be exported to [`pass`](http://passwordstore.org) (from passwordstore.org) using:

```
python firefox_decrypt.py --format pass
```

**All** existing passwords will be exported after the pattern `web/<address>[:<port>]`.
If multiple credentials exist for the same website `/<login>` is appended.
By `pass` convention, the password will be on the first and the username on the second line.

To prefix the username with `login: ` for compatibility with the [browserpass](https://github.com/dannyvankooten/browserpass) extension, you can use:
```
python firefox_decrypt.py --format pass --pass-username-prefix 'login: '
```

There is currently no way to selectively export passwords.

Exporting will overwrite existing passwords without warning. Ensure you have a backup or are using the `pass git` functionality.

#### Non-interactive mode

A non-interactive mode which bypasses all prompts, including profile choice and master password, can be enabled with `-n/--no-interactive`.
If you have multiple Mozilla profiles, make sure to also indicate your profile choice by passing `-c/--choice N` where N is the number of the profile you wish to decrypt (starting from **1**).

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

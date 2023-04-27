#### Changelog

##### 1.0.0+git
- Include `pyproject.toml` to facilitate usage via `pipx`
- Allow overriding default encoding
- Add `--pass-always-with-login` to always include /login as part of pass's password path
- Improve compatibility with `gopass` by explicitly using `pass ls` instead of `pass`

##### 1.0.0
- Improve detection of NSS in Windows and MacOS
- Skip decoding failures or malformed records
- UTF-8 is now required for all interaction
- Python UTF-8 mode is recommended on Windows
- Tests are now automated on Linux, MacOS and Windows

##### 1.0.0-rc1
- Output formats have been internally refactored for easier extensibility.
  There is now 'human', 'csv', 'tabular', 'json' and 'pass'
- This version hopefully fixes the long standing encoding issues in Windows and MacOSX
- `--quotechar` is now `--csv-quotechar`.
- `--delimiter` is now `--csv-delimiter`.
- `--tabular` is now `--format tabular`.
- `--export-pass` is now `--format pass`.
- Drop support for Python 2. Python 3.9 is now the required minimal version.
- Add compatibility with browserpass via `--pass-compat=browserpass`
- Add compatibility mode `username` for a `username:` prefix
- Add `--pass-cmd` to allow specifying pass's location or script name.
- Using `--pass-prefix=''` prevents creation of a prefix: `web/address/...` becomes `address/...`
- Fix an encoding bug due to non-ASCII characters leading to a user's profile path
- Explicitly target 32/64bit Mozilla folders depending on Python bitness

##### 0.7.0
- Fix PK11 slot memory leak
- Configurable pass-export prefix via `--pass-prefix`
- Deprecate `--tabular`, add `--format` parameter and support CSV format
- Fix minor bug with formatting of profile selection prompt
- Support several default locations for libnss on Darwin
- Support for password-store in SQLite format starting with Firefox v59

##### 0.6.2
- Add `--tabular` output

##### 0.6.1
- Fix a bug on `--version` affecting primarily Python 3 (@criztovyl)

##### 0.6
- Fix a bug leading to segmentation fault crashes on newer platforms
- Passing `--version` now displays firefox\_decrypt's version

##### 0.5.4
- Search for NSS on additional folders when on Windows

##### 0.5.3
- Compatibility improvements with Windows and OSX

##### 0.5.2
- Non-interative mode (`-n/--no-interactive`, `-l/--list`, `-c/--choice`)

##### 0.5.1
- Testsuite is now in place

##### 0.5
- Fix encoding/decoding problems in python 2 - #5
- Exporting passwords to *pass* now includes the login name
- Exported password identifiers no longer include login names unless multiple
  credentials exist for the same address.

##### 0.4.2
- If profile\_path provided doesn't contain profiles.ini assume it is an actual profile

##### 0.4.1
- If only a single profile is found do not prompt user for profile
- Document that the tool also works for Thunderbird profiles

##### 0.4
- Add option to export passwords to *pass* from http://passwordstore.org

##### 0.3
- Polyglot Python 2 and 3. Python 3 now supported.
- Improved debugging information with -v or -vv

##### 0.2
- Added support for logins.json. New format since Firefox 32.

##### 0.1
- Initial version supporting Firefox 3.5 and up.

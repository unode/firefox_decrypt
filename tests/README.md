### Running tests

To run all tests, simply run `./run_all`.
Also see section in general README [here](../README.md#testing)

### Writing tests

Tests are executed using the [bash-tap](https://github.com/wbsch/bash_tap) testing framework.

#### Requirements

Tests must meet the following criteria:
- A test must have a `.t` extension.
- In order to be picked up by the `run_all` script, the test must also be executable. (`chmod +x testfile.t`)

#### Test structure

Test files contain the following:

    #!/usr/bin/env bash

    # File containing all testing functionality and helper functions
    . bash_tap_fd.sh

    # Obtain master password used in the test framework
    PASSWD=$(get_password)
    # Basically the firefox_decrypt.py command
    CMD=$(get_script)
    # Test data to use. One of the profiles under tests/test_data/ or the test_data folder itself in which case profile.ini is used.
    TEST="$(get_test_data)"
    # For interactive tests this consists of the commands that a user would type
    PAYLOAD="2\n${PASSWD}"

    # Each line is one test. If the line has a non-zero exit code the test fails
    echo ${PAYLOAD} | ${CMD} --args ${TEST} ...
    # Some tests also use diff and grep to ensure the output matches what is expected


#### Syntax

Some tests make use of some lesser known bash constructs such as `<(command)`.
This syntax is called **process substitution** and is documented [here](http://www.tldp.org/LDP/abs/html/process-sub.html).

#### Existing test profiles

In order to test compatibility with different versions of Firefox there are currently 3 profiles that can be picked from:
- `test_profile_firefox_20` - Firefox 20.0 (uses an sqlite storage backend for secrets)
- `test_profile_firefox_46` - Firefox 46.0 (uses a json storage backend for secrets)
- `test_profile_firefox_nopassword` - Firefox 46.0 (secrets are not protected by a master password)

The password used in the protected profiles lives in `tests/test_data/master_password` and can be obtained by calling the `get_password` helper function in tests.

#### Logins

Each testing profile contains 3 users. Their details are found under `tests/test_data/users/`.
These can be used to validate that `firefox_decrypt` outputs the correct answer, including encoding and handling of special characters.

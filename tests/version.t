#!/usr/bin/env bash
. bash_tap_fd.sh

CMD=$(get_script)
GIT_VERSION="git describe --tags"
EXPECTED_VERSION=$(get_internal_version)

skip_if_not_git || diff -u <(${CMD} --version || kill $$) <($GIT_VERSION)
diff -u <(cd / && ${CMD} --version || kill $$) <($EXPECTED_VERSION)

# vim: ai sts=4 et sw=4

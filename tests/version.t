#!/usr/bin/env bash
. bash_tap_fd.sh

CMD="$(get_script) --version"
GIT_VERSION="git describe --tags"
EXPECTED_VERSION="get_internal_version"

[ "x${GIT_VERSION}" != "x" ]
[ "x${EXPECTED_VERSION}" != "x" ]
skip_if_not_git || diff -u <(${CMD} 2>&1 || kill $$) <($GIT_VERSION)
diff -u <(cd / && ${CMD} 2>&1 || kill $$) <($EXPECTED_VERSION)

# vim: ai sts=4 et sw=4

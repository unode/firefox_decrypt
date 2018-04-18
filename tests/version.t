#!/usr/bin/env bash
. bash_tap_fd.sh

CMD="$(get_script) --version"
EXPECTED_VERSION="get_internal_version"

[ "x${EXPECTED_VERSION}" != "x" ]
diff -u <(cd / && ${CMD} 2>&1 || kill $$) <($EXPECTED_VERSION)

# vim: ai sts=4 et sw=4

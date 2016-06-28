#!/usr/bin/env bash
. bash_tap_fd.sh

CMD="$(get_script) $(get_test_data) -nc 3"


diff -u <(echo "" | ${CMD} ${TEST} | grep -C1 doesntexist) <(get_user_data "doesntexist")
diff -u <(echo "" | ${CMD} ${TEST} | grep -C1 onemore) <(get_user_data "onemore")
diff -u <(echo "" | ${CMD} ${TEST} | grep -C1 cömplex) <(get_user_data "complex")

# vim: ai sts=4 et sw=4

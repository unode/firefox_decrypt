#!/usr/bin/env bash
. bash_tap_fd.sh

PASSWD=$(get_password)
CMD="$(get_script) $(get_test_data) -nc 2"


diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep -C1 doesntexist) <(get_user_data "doesntexist")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep -C1 onemore) <(get_user_data "onemore")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep -C1 cömplex) <(get_user_data "complex")

# vim: ai sts=4 et sw=4

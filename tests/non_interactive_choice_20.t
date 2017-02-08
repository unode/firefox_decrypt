#!/usr/bin/env bash
. bash_tap_fd.sh

PASSWD=$(get_password)
CMD="$(get_script) $(get_test_data) -nc 1"


diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep -C1 doesntexist || kill $$) <(get_user_data "doesntexist")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep -C1 onemore || kill $$) <(get_user_data "onemore")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep -C1 cömplex || kill $$) <(get_user_data "complex")

# vim: ai sts=4 et sw=4

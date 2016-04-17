#!/usr/bin/env bash

source bash_tap_fd.sh

PASSWD=$(get_password)
CMD=$(get_script)
TEST="$(get_test_data)/test_profile_firefox_20/"


# Python 2 tests
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep -C1 doesntexist) <(get_user_data "doesntexist")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep -C1 onemore) <(get_user_data "onemore")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep -C1 cömplex) <(get_user_data "complex")

# vim: ai sts=4 et sw=4

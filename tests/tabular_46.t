#!/usr/bin/env bash
. bash_tap_fd.sh

PASSWD=$(get_password)
CMD="$(get_script) --tabular"
TEST="$(get_test_data)/test_profile_firefox_46/"


diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep doesntexist || kill $$) <(get_user_data "doesntexist_tabular")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep onemore || kill $$) <(get_user_data "onemore_tabular")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep cömplex || kill $$) <(get_user_data "complex_tabular")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep jãmïe || kill $$) <(get_user_data "jamie_tabular")

# vim: ai sts=4 et sw=4

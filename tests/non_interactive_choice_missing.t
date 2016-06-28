#!/usr/bin/env bash
. bash_tap_fd.sh

PASSWD=$(get_password)
CMD=$(get_script)
TEST="$(get_test_data)"


diff -u <(echo ${PASSWD} | ${CMD} ${TEST} -n 2>&1 | remove_log_date_time; echo ${PIPESTATUS[1]}) <(get_output_data "non_interactive_choice_missing")

# vim: ai sts=4 et sw=4

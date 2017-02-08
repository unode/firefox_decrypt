#!/usr/bin/env bash
. bash_tap_fd.sh

PASSWD=$(get_password)
CMD=$(get_script)
TEST="$(get_test_data)"


diff -u <(${CMD} -l ${TEST} || kill $$) <(get_output_data "list")

# vim: ai sts=4 et sw=4

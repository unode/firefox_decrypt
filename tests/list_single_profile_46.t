#!/usr/bin/env bash
. bash_tap_fd.sh

PASSWD=$(get_password)
CMD=$(get_script)
TEST="$(get_test_data)/test_profile_firefox_46"


# The first process substitution is rather complex:
# As first we're interested in stderr, so 2>&1.
# get_test_data() generates an absolute path, so we need to make it relative (as the path would be different for each tester)
# last but not least we're also interested in the exit code.

diff -u <(${CMD} -l ${TEST} 2>&1 | remove_log_date_time | sed "s|${bashtap_org_pwd}/||g"; echo ${PIPESTATUS[0]}) <(get_output_data "list_single_46")

# vim: ai sts=4 et sw=4

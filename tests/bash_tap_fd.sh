#!/usr/bin/env bash
# This file only contains helper functions for making testing easier.
# The magic happens in bash_tap.sh sourced at the end of this file.

function get_password {
    echo "$(cat ${bashtap_org_pwd}/test_data/master_password)"
}

function get_script {
    echo "/usr/bin/env python ${bashtap_org_pwd}/../firefox_decrypt.py"
}

function get_test_data {
    echo "${bashtap_org_pwd}/test_data"
}

function get_user_data {
    echo -e "$(cat ${bashtap_org_pwd}/test_data/users/${1}.user)"
}

function get_output_data {
    echo -e "$(cat ${bashtap_org_pwd}/test_data/outputs/${1}.output)"
}

function get_internal_version {
    echo -e "$(grep '##.*\.' ${bashtap_org_pwd}/../CHANGELOG.md | head -n 1 | cut -d ' ' -f 2)"
}

# Cut out the first two fields, from log as they are date and time (which would make it impossible to test ;D)
function remove_log_date_time {
    cat - | cut -d" " -f3-
}

# Include the base script that does the actual work.
source bash_tap.sh

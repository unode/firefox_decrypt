#!/usr/bin/env bash
# This file only contains helper functions for making testing easier.
# The magic happens in bash_tap.sh sourced at the end of this file.
#
# Subject to the MIT License. See LICENSE file or http://opensource.org/licenses/MIT
# Copyright (c) 2015-2016 Wilhelm Schürmann

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

# Include the base script that does the actual work.
source bash_tap.sh

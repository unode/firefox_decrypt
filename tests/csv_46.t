#!/usr/bin/env bash
. bash_tap_fd.sh

PASSWD=$(get_password)
CMD="$(get_script) --format csv"
TEST="$(get_test_data)/test_profile_firefox_46/"

diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | head -n 1 || kill $$) <(get_user_data "header_csv_default")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep doesntexist || kill $$) <(get_user_data "doesntexist_csv_default")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep onemore || kill $$) <(get_user_data "onemore_csv_default")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep cömplex || kill $$) <(get_user_data "complex_csv_default")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep jãmïe || kill $$) <(get_user_data "jamie_csv_default")

CMD="$(get_script) --format csv --delimiter \t --quotechar '"

diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | head -n 1 || kill $$) <(get_user_data "header_csv_tabular")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep doesntexist || kill $$) <(get_user_data "doesntexist_tabular")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep onemore || kill $$) <(get_user_data "onemore_tabular")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep cömplex || kill $$) <(get_user_data "complex_tabular")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep jãmïe || kill $$) <(get_user_data "jamie_tabular")

CMD="$(get_script) --format csv --delimiter ; --quotechar '"

diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | head -n 1 || kill $$) <(get_user_data "header_csv_semicol_singlequot")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep doesntexist || kill $$) <(get_user_data "doesntexist_csv_semicol_singlequot")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep onemore || kill $$) <(get_user_data "onemore_csv_semicol_singlequot")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep cömplex || kill $$) <(get_user_data "complex_csv_semicol_singlequot")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep jãmïe || kill $$) <(get_user_data "jamie_csv_semicol_singlequot")

CMD="$(get_script) --format csv --delimiter \t --quotechar |"

diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | head -n 1 || kill $$) <(get_user_data "header_csv_tab_vertbar")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep doesntexist || kill $$) <(get_user_data "doesntexist_csv_tab_vertbar")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep onemore || kill $$) <(get_user_data "onemore_csv_tab_vertbar")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep cömplex || kill $$) <(get_user_data "complex_csv_tab_vertbar")
diff -u <(echo ${PASSWD} | ${CMD} ${TEST} | grep jãmïe || kill $$) <(get_user_data "jamie_csv_tab_vertbar")

# vim: ai sts=4 et sw=4

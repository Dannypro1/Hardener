#!/usr/bin/env bash
set -Eeuo pipefail
# shellcheck source=_helpers.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_helpers.sh"
# shellcheck source=../lib/customize.sh
source "${HARDENER_ROOT}/lib/customize.sh"

printf 'test_customize\n'

SELECTED_MODULES=(users kernel network)
mapfile -t rel < <(relevant_defenses)
joined="${rel[*]}"
assert_contains "$joined" "USER_LOCK_EMPTY_PASSWORDS" "users defenses are listed"
assert_contains "$joined" "KERNEL_BLACKLIST_USB" "kernel defenses are listed"
assert_not_contains "$joined" "FAIL2BAN_ENABLED" "fail2ban hidden when module not selected"

USER_LOCK_EMPTY_PASSWORDS=true
toggle_defense_flag USER_LOCK_EMPTY_PASSWORDS
assert_eq "$USER_LOCK_EMPTY_PASSWORDS" "false" "toggle turns a flag off"
toggle_defense_flag USER_LOCK_EMPTY_PASSWORDS
assert_eq "$USER_LOCK_EMPTY_PASSWORDS" "true" "toggle turns a flag back on"

parse_set_option "FS_TMP_NOEXEC=true"
assert_eq "$FS_TMP_NOEXEC" "true" "--set applies a known defense flag"

if ( parse_set_option "NOT_A_REAL_FLAG=true" ) 2>/dev/null; then rc=0; else rc=1; fi
assert_false "unknown --set variable is rejected" "$rc"

test_summary test_customize

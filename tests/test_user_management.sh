#!/usr/bin/env bash
set -Eeuo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_helpers.sh"
source "${MODULE_DIR}/user_management.sh"

printf 'test_user_management\n'
calls=''
fail_user=''
_users_ensure_login_account() {
  calls+="account:$1;"
  [[ "$1" != "$fail_user" ]]
}
module_ssh_apply() { calls+="ssh:${SSH_ALLOW_USERS};"; }
SSH_ALLOW_USERS='existing'
module_user_management_apply
assert_eq "$calls" 'account:ange;account:spencer;ssh:existing,ange,spencer;' 'onboards both accounts before applying SSH'
_user_management_allow_users
assert_eq "$SSH_ALLOW_USERS" 'existing,ange,spencer' 'allowlist merge avoids duplicates'

calls=''
fail_user=ange
if module_user_management_apply; then rc=0; else rc=1; fi
assert_false 'account failure fails onboarding' "$rc"
assert_eq "$calls" 'account:ange;' 'account failure prevents SSH application'

parse_module_selection 21
PROFILE_NAME_SELECTED=trac
NON_INTERACTIVE=false
select_modules_interactive
assert_eq "${SELECTED_MODULES[*]}" user_management 'explicit option 21 overrides profile without another menu'
test_summary test_user_management

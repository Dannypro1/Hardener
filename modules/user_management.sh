#!/usr/bin/env bash
# Targeted onboarding, separate from the general User Security controls.
source "${MODULE_DIR}/users.sh"
source "${MODULE_DIR}/ssh.sh"

_user_management_allow_users() {
  local name
  for name in ange spencer; do
    if ! _users_is_allowuser "$name"; then
      SSH_ALLOW_USERS="${SSH_ALLOW_USERS:+${SSH_ALLOW_USERS},}${name}"
    fi
  done
}

module_user_management_plan() {
  printf '  Ensure ange (Ange Gakwandi) and spencer (Spencer Kamayo)\n'
  printf '  Admin group: %s (selected from detected OS unless overridden)\n' "$(_users_sudo_group)"
  printf '  Prompt for new accounts temporary passwords; require change at first login\n'
  printf '  Preserve established passwords on repeat runs\n'
  printf '  Add both accounts to SSH AllowUsers, retaining configured users\n'
  local SSH_ALLOW_USERS="${SSH_ALLOW_USERS:-}"
  _user_management_allow_users
  module_ssh_plan
}

module_user_management_apply() {
  local SSH_ENSURE_FULL_NAMES='ange:Ange Gakwandi;spencer:Spencer Kamayo'
  local SSH_TEMP_PASSWORD_USERS='ange,spencer'
  local SSH_ENSURE_SUDO=true
  _users_ensure_login_account ange || return 1
  _users_ensure_login_account spencer || return 1
  _user_management_allow_users
  module_ssh_apply
}

module_user_management_audit() {
  module_users_audit
  module_ssh_audit
}

module_user_management_validate() {
  module_ssh_validate
}

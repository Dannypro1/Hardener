#!/usr/bin/env bash
set -Eeuo pipefail
# shellcheck source=_helpers.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_helpers.sh"
# shellcheck source=../modules/users.sh
source "${HARDENER_ROOT}/modules/users.sh"

printf 'test_users\n'

SSH_ALLOW_USERS="sys-trac,danny"
if _users_is_allowuser "danny"; then rc=0; else rc=1; fi
assert_true "danny is an AllowUsers account" "$rc"
if _users_is_allowuser "ubuntu"; then rc=0; else rc=1; fi
assert_false "ubuntu is not an AllowUsers account" "$rc"

nologin="$(_users_nologin_shell)"
if [[ "$nologin" == *nologin* || "$nologin" == *false* ]]; then rc=0; else rc=1; fi
assert_true "nologin helper returns a nologin or false path" "$rc"

# Mock privileged commands: these tests never create real accounts.
calls="$(mktemp)"
trap 'rm -f "$calls"' EXIT
changes_allowed() { [[ "$MODE" == apply ]]; }
id() { [[ "$account_exists" == true ]]; }
getent() {
  case "$1" in
    group) [[ "$group_exists" == true ]] ;;
    shadow) printf '%s:%s:%s:0:99999:7:::\n' "$2" "$account_hash" "$account_date" ;;
  esac
}
useradd() { printf 'useradd %s\n' "$*" >> "$calls"; account_exists=true; }
usermod() { printf 'usermod %s\n' "$*" >> "$calls"; }
passwd() { printf 'passwd %s\n' "$*" >> "$calls"; return "$passwd_rc"; }
chage() { printf 'chage %s\n' "$*" >> "$calls"; }
MODE=apply
NON_INTERACTIVE=false
SSH_ENSURE_SUDO=true
SSH_ENSURE_SUDO_GROUP=sudo
SSH_ENSURE_FULL_NAMES='ange:Ange Gakwandi;spencer:Spencer Kamayo'
SSH_TEMP_PASSWORD_USERS='ange,spencer'
group_exists=true
passwd_rc=0
account_hash='!'
account_date=20000
for name in ange spencer; do
  account_exists=false
  : > "$calls"
  _users_ensure_login_account "$name"
  content="$(cat "$calls")"
  case "$name" in
    ange) fullname='Ange Gakwandi' ;;
    spencer) fullname='Spencer Kamayo' ;;
  esac
  assert_contains "$content" "useradd -m -s /bin/bash -c $fullname $name" "creates $name with full name"
  assert_contains "$content" "usermod -aG sudo $name" "adds $name to sudo"
  assert_contains "$content" "passwd $name" "prompts for $name password"
  assert_eq "$(tail -n 1 "$calls")" "chage -d 0 $name" "expires $name password after setting it"
done
account_exists=true
account_hash='hashed-password'
: > "$calls"
_users_ensure_login_account ange
assert_not_contains "$(cat "$calls")" 'passwd ' 'rerun preserves established password'
assert_not_contains "$(cat "$calls")" 'chage ' 'rerun does not expire established password'

account_exists=false
account_hash='!'
NON_INTERACTIVE=true
: > "$calls"
_users_ensure_login_account ange
assert_not_contains "$(cat "$calls")" 'passwd ' 'noninteractive setup does not prompt'
assert_contains "$(cat "$calls")" 'chage -d 0 ange' 'noninteractive setup marks password pending'

account_exists=true
account_date=0
NON_INTERACTIVE=false
: > "$calls"
_users_ensure_login_account ange
assert_contains "$(cat "$calls")" 'passwd ange' 'interactive rerun resumes pending setup'

account_exists=false
passwd_rc=1
if _users_ensure_login_account ange; then rc=0; else rc=1; fi
assert_false 'password failure propagates' "$rc"
passwd_rc=0
group_exists=false
: > "$calls"
if _users_ensure_login_account ange; then rc=0; else rc=1; fi
assert_false 'missing sudo group fails provisioning' "$rc"
assert_eq "$(cat "$calls")" '' 'missing sudo group makes no account changes'

MODE=dry-run
: > "$calls"
_users_ensure_login_account ange
assert_eq "$(cat "$calls")" '' 'dry run makes no account changes'

load_all_config
source "${HARDENER_ROOT}/modules/ssh.sh"
for name in ange spencer; do
  assert_contains "$(_ssh_build_dropin)" " $name" "org SSH allowlist includes $name"
done
load_profile trac
assert_contains "$(_ssh_build_dropin)" 'AllowUsers sys-trac danny ange spencer' 'TRAC retains all SSH accounts'

test_summary test_users

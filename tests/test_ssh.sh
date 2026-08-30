#!/usr/bin/env bash
set -Eeuo pipefail
# shellcheck source=_helpers.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_helpers.sh"
# shellcheck source=../modules/ssh.sh
source "${HARDENER_ROOT}/modules/ssh.sh"

printf 'test_ssh\n'

SSH_DISABLE_ROOT_LOGIN=true
SSH_DISABLE_PASSWORD_AUTH=false
SSH_PERMIT_EMPTY_PASSWORDS=false
SSH_PORT=""
content="$(_ssh_build_dropin)"

assert_contains "$content" "PermitRootLogin no" "drop-in disables root login"
assert_contains "$content" "PasswordAuthentication yes" "drop-in keeps password authentication"
assert_contains "$content" "PubkeyAuthentication yes" "drop-in enables pubkey authentication"
assert_contains "$content" "ChallengeResponseAuthentication no" "drop-in disables challenge-response"
assert_contains "$content" "MaxAuthTries 3" "drop-in limits auth tries"
assert_contains "$content" "PermitEmptyPasswords no" "drop-in disables empty passwords"
assert_not_contains "$content" "PasswordAuthentication no" "drop-in does not force PasswordAuthentication no"

SSH_ALLOW_USERS="sys-trac,danny"
content="$(_ssh_build_dropin)"
assert_contains "$content" "AllowUsers sys-trac danny" "drop-in writes AllowUsers"

IS_SSH_SESSION=true
CURRENT_SSH_USER="ubuntu"
SSH_ALLOW_USERS="sys-trac,danny"
_ssh_protect_current_user
assert_contains "$SSH_ALLOW_USERS" "ubuntu" "current SSH user is appended to AllowUsers"
if grep -q '^Port ' <<<"$content"; then rc=0; else rc=1; fi
assert_false "drop-in does not set Port when SSH_PORT is empty" "$rc"

SSH_PORT="2222"
content="$(_ssh_build_dropin)"
assert_contains "$content" "Port 2222" "drop-in sets custom port when configured"

IS_SSH_SESSION=true
CURRENT_SSH_USER="admin"
SSH_ALLOW_USERS="admin,deploy"
if _ssh_would_lock_current_user; then rc=0; else rc=1; fi
assert_false "current user listed in AllowUsers is not a lockout" "$rc"

SSH_ALLOW_USERS="deploy"
if _ssh_would_lock_current_user; then rc=0; else rc=1; fi
assert_true "AllowUsers excluding current user is a lockout" "$rc"
assert_contains "${SSH_LOCKOUT_REASON}" "AllowUsers would exclude" "lockout reason names AllowUsers"

SSH_ALLOW_USERS=""
SSH_DENY_USERS="admin"
if _ssh_would_lock_current_user; then rc=0; else rc=1; fi
assert_true "DenyUsers including current user is a lockout" "$rc"
assert_contains "${SSH_LOCKOUT_REASON}" "DenyUsers includes" "lockout reason names DenyUsers"

test_summary test_ssh

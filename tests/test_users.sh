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

test_summary test_users

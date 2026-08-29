#!/usr/bin/env bash
set -Eeuo pipefail
# shellcheck source=_helpers.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_helpers.sh"
# shellcheck source=../modules/firewall.sh
source "${HARDENER_ROOT}/modules/firewall.sh"

printf 'test_firewall\n'

FIREWALL_BACKEND="ufw"
SSH_PORT=""
SSH_PORT_CURRENT="22"
assert_eq "$(_fw_backend)" "ufw" "backend override works"
assert_eq "$(_fw_ssh_port)" "22" "default SSH port is current port"

SSH_PORT="2222"
assert_eq "$(_fw_ssh_port)" "2222" "configured SSH port wins"

FIREWALL_ALLOWED_PORTS="80,443"
ports="$(_fw_extra_ports | tr '\n' ',')"
assert_contains "$ports" "80" "extra ports include 80"
assert_contains "$ports" "443" "extra ports include 443"

SSH_PORT_CURRENT="22"
SSH_PORT=""
proposal="$(_fw_show_proposal)"
assert_contains "$proposal" "22" "proposal mentions SSH port"

test_summary test_firewall

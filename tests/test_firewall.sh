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

if _fw_valid_port "80"; then rc=0; else rc=1; fi
assert_true "plain port 80 is valid" "$rc"
if _fw_valid_port "53/udp"; then rc=0; else rc=1; fi
assert_true "53/udp is valid" "$rc"
if _fw_valid_port "99999"; then rc=0; else rc=1; fi
assert_false "port 99999 is invalid" "$rc"
if _fw_valid_addr "10.0.0.1"; then rc=0; else rc=1; fi
assert_true "IPv4 is valid" "$rc"
if _fw_valid_addr "10.0.0.0/8"; then rc=0; else rc=1; fi
assert_true "CIDR is valid" "$rc"
if _fw_valid_addr "not-an-ip"; then rc=0; else rc=1; fi
assert_false "junk address is invalid" "$rc"

assert_eq "$(_fw_normalize_list "80,443,nope,53/udp" port)" "80,443,53/udp" "port list drops invalid entries"
assert_eq "$(_fw_normalize_list "10.0.0.1,bad,10.1.0.0/16" addr)" "10.0.0.1,10.1.0.0/16" "addr list drops invalid entries"

SSH_PORT="22"
SSH_PORT_CURRENT="22"
FIREWALL_ALLOWED_PORTS="80"
FIREWALL_INBOUND_SOURCES=""
rules="$(_fw_each_inbound_allow)"
assert_contains "$rules" "tcp 22" "inbound rules include SSH"
assert_contains "$rules" "tcp 80" "inbound rules include extra port"

FIREWALL_INBOUND_SOURCES="203.0.113.10"
rules="$(_fw_each_inbound_allow)"
assert_contains "$rules" "203.0.113.10" "inbound rules include source IP"

SSH_CONNECTION="198.51.100.20 51234 10.0.0.5 22"
FIREWALL_INBOUND_SOURCES="10.0.0.0/8"
_fw_protect_ssh_source
assert_contains "$FIREWALL_INBOUND_SOURCES" "198.51.100.20" "current SSH client is added to sources"

SSH_PORT=""
SSH_PORT_CURRENT="22"
FIREWALL_ALLOWED_PORTS="80,443"
FIREWALL_INBOUND_SOURCES="10.0.0.1"
FIREWALL_OUTBOUND_PORTS="443"
FIREWALL_ALLOW_OUTBOUND=false
proposal="$(_fw_show_proposal)"
assert_contains "$proposal" "22" "proposal mentions SSH port"
assert_contains "$proposal" "10.0.0.1" "proposal mentions inbound source"
assert_contains "$proposal" "443" "proposal mentions outbound port"

test_summary test_firewall

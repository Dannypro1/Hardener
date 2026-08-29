#!/usr/bin/env bash
set -Eeuo pipefail
# shellcheck source=_helpers.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_helpers.sh"
# shellcheck source=../modules/kernel.sh
source "${HARDENER_ROOT}/modules/kernel.sh"
# shellcheck source=../modules/network.sh
source "${HARDENER_ROOT}/modules/network.sh"
# shellcheck source=../modules/services.sh
source "${HARDENER_ROOT}/modules/services.sh"

printf 'test_defense\n'

bl="$(_kernel_modprobe_content)"
assert_contains "$bl" "install dccp /bin/true" "blacklist disables dccp"
assert_contains "$bl" "install sctp /bin/true" "blacklist disables sctp"
assert_contains "$bl" "blacklist cramfs" "blacklist uncommon filesystem cramfs"
assert_not_contains "$bl" "usb-storage" "USB storage is not blacklisted by default"

KERNEL_BLACKLIST_USB=true
bl="$(_kernel_modprobe_content)"
assert_contains "$bl" "usb-storage" "USB storage blacklist is opt-in"

net="$(_net_sysctl_content)"
assert_contains "$net" "tcp_syncookies = 1" "network defense enables SYN cookies"
assert_contains "$net" "rp_filter = 1" "network defense enables rp_filter"
assert_contains "$net" "accept_redirects = 0" "network defense disables ICMP redirects"
assert_not_contains "$net" "disable_ipv6" "IPv6 is not disabled in the default net sysctl"

hc="$(_net_host_conf)"
assert_contains "$hc" "order hosts,bind" "host.conf sets resolver order"

assert_contains "$DANGEROUS_SERVICES" "telnet" "telnet is in the auto-disable list"
assert_contains "$DANGEROUS_SERVICES" "rsh" "rsh is in the auto-disable list"
assert_contains "$REVIEW_SERVICES" "avahi-daemon" "avahi still requires confirmation"

test_summary test_defense

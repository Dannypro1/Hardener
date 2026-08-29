#!/usr/bin/env bash
# Network audit. IPv6 is never disabled automatically.

module_network_audit() {
  local ifaces
  ifaces="$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | tr '\n' ',' | sed 's/,$//' || echo unknown)"
  record_finding "Interfaces" "INFO" "INFO" "Network interfaces" "$ifaces" "documented interfaces only" \
    "Disable unused interfaces in the OS network config if appropriate" "CIS 3.1"

  if have_cmd ss; then
    local listeners
    listeners="$(ss -lntupH 2>/dev/null | awk '{print $5}' | tr '\n' ',' | sed 's/,$//')"
    record_finding "Listeners" "INFO" "INFO" "Listening sockets" "${listeners:-none}" "required services only" \
      "Stop unused listeners" "CIS Control 12"
  fi

  if [[ -r /etc/resolv.conf ]]; then
    local ns
    ns="$(awk '/^nameserver/ {print $2}' /etc/resolv.conf | tr '\n' ',' | sed 's/,$//')"
    record_finding "DNS" "INFO" "INFO" "Configured nameservers" "${ns:-none}" "trusted resolvers" \
      "Review resolv.conf / systemd-resolved" "CIS 3.1"
  fi

  if [[ -r /proc/sys/net/ipv6/conf/all/disable_ipv6 ]]; then
    local v6
    v6="$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)"
    record_finding "IPv6" "INFO" "INFO" \
      "IPv6 disable flag (tool will not change this automatically)" \
      "$v6" "leave enabled unless policy requires otherwise" \
      "Do not disable IPv6 unless applications and DNS are IPv4-only" "CIS 3.1.2"
  fi
}

module_network_plan() {
  printf '  Audit interfaces, listeners, routing, DNS, IPv4/IPv6\n'
  printf '  IPv6 is not disabled\n'
  printf '  Disruptive sysctl lives in the sysctl module\n'
}

module_network_apply() {
  log_info "Network module is audit-oriented. Sysctl network knobs are applied by the sysctl module."
}

module_network_validate() {
  return 0
}

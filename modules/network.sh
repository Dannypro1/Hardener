#!/usr/bin/env bash
# Network defenses. IPv6 is never disabled unless NETWORK_DISABLE_IPV6=true.

NETWORK_SYSCTL_FILE="/etc/sysctl.d/98-server-hardening-net.conf"
NETWORK_DISABLE_IPV6="${NETWORK_DISABLE_IPV6:-false}"

_net_sysctl_content() {
  cat <<'EOF'
# Managed by Server Hardener — host network stack defenses
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF
  if is_true "${SYSCTL_DISABLE_IP_FORWARD:-true}"; then
    cat <<'EOF'
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
EOF
  fi
}

_net_host_conf() {
  cat <<'EOF'
# Managed by Server Hardener
order hosts,bind
multi on
EOF
}

module_network_audit() {
  local ifaces
  ifaces="$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | tr '\n' ',' | sed 's/,$//' || echo unknown)"
  record_finding "Interfaces" "INFO" "INFO" "Network interfaces" "$ifaces" "documented interfaces only" \
    "This module does not disable interfaces" "CIS 3.1"

  if have_cmd ss; then
    local listeners
    listeners="$(ss -lntupH 2>/dev/null | awk '{print $5}' | tr '\n' ',' | sed 's/,$//')"
    record_finding "Listeners" "INFO" "INFO" "Listening sockets" "${listeners:-none}" "required services only" \
      "Stop unused listeners; firewall module restricts inbound" "CIS Control 12"
  fi

  if [[ -f "$NETWORK_SYSCTL_FILE" ]]; then
    record_finding "Network Sysctl" "PASS" "INFO" "Managed network sysctl is present" \
      "$NETWORK_SYSCTL_FILE" "present" "No action" "CIS 3.3"
  else
    record_finding "Network Sysctl" "WARN" "MEDIUM" "Network stack defenses not deployed" \
      "absent" "$NETWORK_SYSCTL_FILE" "Apply the network module" "CIS 3.3"
  fi

  if [[ -r /proc/sys/net/ipv6/conf/all/disable_ipv6 ]]; then
    local v6
    v6="$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)"
    record_finding "IPv6" "INFO" "INFO" \
      "IPv6 disable flag (not changed unless NETWORK_DISABLE_IPV6=true)" \
      "$v6" "leave enabled unless policy requires otherwise" \
      "Do not disable IPv6 unless applications and DNS are IPv4-only" "CIS 3.1.2"
  fi
}

module_network_plan() {
  printf '  Write %s (SYN cookies, rp_filter, no redirects, log martians)\n' "$NETWORK_SYSCTL_FILE"
  printf '  Harden /etc/host.conf and restrict network file modes\n'
  printf '  IPv6 remains enabled (NETWORK_DISABLE_IPV6=%s)\n' "$NETWORK_DISABLE_IPV6"
}

_net_secure_file() {
  local path="$1"
  local mode="$2"
  [[ -e "$path" ]] || return 0
  local cur
  cur="$(file_mode "$path" || true)"
  if [[ "$cur" == "$mode" ]]; then
    return 0
  fi
  # resolv.conf is often a symlink to systemd-resolved — skip chmod on links.
  if [[ -L "$path" ]]; then
    return 0
  fi
  backup_file "$path" network
  log_action "chmod ${mode} ${path}"
  if changes_allowed; then
    chmod "$mode" "$path"
  fi
}

module_network_apply() {
  announce_defense NETWORK_APPLY_SYSCTL "Network stack sysctl defenses"
  announce_defense NETWORK_DISABLE_IPV6 "Disable IPv6"

  if is_true "${NETWORK_APPLY_SYSCTL:-true}"; then
    write_managed_file "$NETWORK_SYSCTL_FILE" 0644 network < <(_net_sysctl_content)
    if [[ -f /etc/host.conf ]] || changes_allowed || is_dry_run; then
      if [[ -f /etc/host.conf ]]; then
        backup_file /etc/host.conf network
      fi
      write_managed_file /etc/host.conf 0644 network < <(_net_host_conf)
    fi
    _net_secure_file /etc/hosts 644
    _net_secure_file /etc/resolv.conf 644
    _net_secure_file /etc/nsswitch.conf 644
  fi

  if is_true "$NETWORK_DISABLE_IPV6"; then
    log_warning "NETWORK_DISABLE_IPV6=true — writing IPv6 disable sysctl (applications may break)"
    write_managed_file /etc/sysctl.d/97-server-hardening-noipv6.conf 0644 network <<'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
  fi

  if is_true "${NETWORK_APPLY_SYSCTL:-true}" || is_true "$NETWORK_DISABLE_IPV6"; then
    if changes_allowed && have_cmd sysctl; then
      sysctl --system >/dev/null 2>&1 || true
      log_success "Network sysctl defenses applied"
    else
      log_action "Would apply network sysctl defenses"
    fi
  fi
}

module_network_validate() {
  if [[ -f "$NETWORK_SYSCTL_FILE" ]]; then
    validate_sysctl_file "$NETWORK_SYSCTL_FILE" || true
  fi
  return 0
}

#!/usr/bin/env bash
# Managed sysctl drop-in. Does not scatter edits across existing files.

SYSCTL_FILE="/etc/sysctl.d/99-server-hardening.conf"
SYSCTL_DISABLE_IP_FORWARD="${SYSCTL_DISABLE_IP_FORWARD:-true}"

_sysctl_content() {
  cat <<EOF
# Managed by Server Hardener. Role-aware: IP forwarding is ${SYSCTL_DISABLE_IP_FORWARD}.

# Kernel information exposure
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 1
kernel.kexec_load_disabled = 1
kernel.yama.ptrace_scope = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Network — source routing / redirects
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# SYN cookies / ICMP
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# IPv6 redirects / source routing (IPv6 is not disabled)
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF
  if is_true "$SYSCTL_DISABLE_IP_FORWARD"; then
    cat <<'EOF'

net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
EOF
  else
    cat <<'EOF'

# IP forwarding left unchanged (router, container, or proxy role).
EOF
  fi
}

module_sysctl_audit() {
  if [[ -f "$SYSCTL_FILE" ]]; then
    record_finding "Sysctl" "PASS" "INFO" \
      "Managed sysctl file is present" "$SYSCTL_FILE" "managed drop-in" \
      "No action" "CIS 3.1 / 3.3"
  else
    record_finding "Sysctl" "WARN" "MEDIUM" \
      "Managed sysctl file is missing" "absent" "$SYSCTL_FILE" \
      "Apply the sysctl module" "CIS 3.1"
  fi
  if [[ -r /proc/sys/net/ipv4/ip_forward ]]; then
    local fwd
    fwd="$(cat /proc/sys/net/ipv4/ip_forward)"
    if is_true "$SYSCTL_DISABLE_IP_FORWARD" && [[ "$fwd" != "0" ]]; then
      record_finding "IP Forwarding" "WARN" "MEDIUM" \
        "IPv4 forwarding is enabled" "$fwd" "0 for non-router hosts" \
        "Set net.ipv4.ip_forward=0 or set SYSCTL_DISABLE_IP_FORWARD=false for routers" \
        "CIS 3.1.1"
    else
      record_finding "IP Forwarding" "PASS" "INFO" \
        "Forwarding matches the configured role" "$fwd" "role-dependent" \
        "No action" "CIS 3.1.1"
    fi
  fi
}

module_sysctl_plan() {
  printf '  Write %s\n' "$SYSCTL_FILE"
  printf '  IP forwarding disabled: %s\n' "$SYSCTL_DISABLE_IP_FORWARD"
  printf '  Apply with sysctl --system\n'
  printf '  Existing sysctl files are not rewritten\n'
}

module_sysctl_apply() {
  local content
  content="$(_sysctl_content)"
  write_managed_file "$SYSCTL_FILE" 0644 sysctl <<<"$content"
  if changes_allowed && have_cmd sysctl; then
    if sysctl --system >/dev/null 2>&1; then
      log_success "sysctl --system applied"
    else
      log_warning "sysctl --system reported errors (some keys may be unavailable)"
      sysctl --system || true
    fi
  else
    log_action "Would run sysctl --system"
  fi
}

module_sysctl_validate() {
  if [[ -f "$SYSCTL_FILE" ]]; then
    validate_sysctl_file "$SYSCTL_FILE"
  fi
}

#!/usr/bin/env bash
# Optional Fail2ban for SSH. Configuration is validated before restart.

FAIL2BAN_ENABLED="${FAIL2BAN_ENABLED:-true}"
FAIL2BAN_BANTIME="${FAIL2BAN_BANTIME:-1h}"
FAIL2BAN_FINDTIME="${FAIL2BAN_FINDTIME:-10m}"
FAIL2BAN_MAXRETRY="${FAIL2BAN_MAXRETRY:-5}"

_f2b_pkg() {
  printf 'fail2ban'
}

module_fail2ban_audit() {
  if have_cmd fail2ban-client && svc_is_active fail2ban; then
    record_finding "Fail2ban" "PASS" "INFO" "fail2ban is running" "active" "active if desired" \
      "No action" "CIS Control 13"
  elif is_true "$FAIL2BAN_ENABLED"; then
    record_finding "Fail2ban" "WARN" "LOW" "fail2ban is not running" "inactive" "active" \
      "Apply the fail2ban module" "CIS Control 13"
  else
    record_finding "Fail2ban" "INFO" "INFO" "fail2ban is optional and disabled" "disabled" "optional" \
      "No action" "CIS Control 13"
  fi
}

module_fail2ban_plan() {
  printf '  Install fail2ban if missing\n'
  printf '  Jail sshd: bantime=%s findtime=%s maxretry=%s\n' \
    "$FAIL2BAN_BANTIME" "$FAIL2BAN_FINDTIME" "$FAIL2BAN_MAXRETRY"
  printf '  Validate configuration before restart\n'
}

module_fail2ban_apply() {
  if is_false "$FAIL2BAN_ENABLED"; then
    log_info "Fail2ban disabled in configuration"
    return 0
  fi
  install_package "$(_f2b_pkg)" || {
    log_warning "fail2ban package not available"
    return 0
  }

  backup_paths fail2ban /etc/fail2ban
  local jail="/etc/fail2ban/jail.d/99-server-hardening.conf"
  local ssh_jail="sshd"
  local content
  content="$(cat <<EOF
[DEFAULT]
bantime  = ${FAIL2BAN_BANTIME}
findtime = ${FAIL2BAN_FINDTIME}
maxretry = ${FAIL2BAN_MAXRETRY}

[${ssh_jail}]
enabled = true
port    = $(_ssh_port_for_f2b)
EOF
)"
  write_managed_file "$jail" 0644 fail2ban <<<"$content"

  if have_cmd fail2ban-client && changes_allowed; then
    if fail2ban-client -t >/dev/null 2>&1; then
      svc_enable fail2ban
      svc_restart fail2ban
    else
      log_error "fail2ban-client -t failed; service not restarted"
      fail2ban-client -t || true
      return 1
    fi
  else
    log_action "Would validate and restart fail2ban"
  fi
}

_ssh_port_for_f2b() {
  if [[ -n "${SSH_PORT:-}" ]]; then
    printf '%s' "$SSH_PORT"
  else
    printf '%s' "${SSH_PORT_CURRENT:-22}"
  fi
}

module_fail2ban_validate() {
  if have_cmd fail2ban-client && is_true "$FAIL2BAN_ENABLED"; then
    fail2ban-client -t >/dev/null 2>&1 || return 1
  fi
  return 0
}

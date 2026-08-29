#!/usr/bin/env bash
# Sudo audit and safe defaults. Never writes sudoers without visudo -cf.

module_sudo_audit() {
  if [[ ! -f /etc/sudoers ]]; then
    record_finding "Sudo" "SKIP" "INFO" "sudoers not present" "missing" "present if sudo is used" "Install sudo if required" "CIS 5.2"
    return 0
  fi

  local mode owner
  mode="$(file_mode /etc/sudoers || echo '?')"
  owner="$(file_owner /etc/sudoers || echo '?')"
  if [[ "$mode" == "440" || "$mode" == "400" ]]; then
    record_finding "Sudoers Permissions" "PASS" "INFO" \
      "sudoers mode is restrictive" "mode=${mode} owner=${owner}" "0440 root:root" \
      "No action" "CIS 5.2.1"
  else
    record_finding "Sudoers Permissions" "FAIL" "HIGH" \
      "sudoers has unexpected permissions" "mode=${mode} owner=${owner}" "0440 root:root" \
      "chmod 0440 /etc/sudoers && chown root:root /etc/sudoers" "CIS 5.2.1"
  fi

  if grep -REn '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -vq 'sudoers.d/README'; then
    record_finding "Sudo NOPASSWD" "WARN" "HIGH" \
      "NOPASSWD rules found" \
      "$(grep -REn '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | head -n 5 | tr '\n' ';')" \
      "Password required except documented break-glass" \
      "Review NOPASSWD entries; do not remove automation accounts blindly" \
      "CIS 5.2.4"
  else
    record_finding "Sudo NOPASSWD" "PASS" "INFO" \
      "No NOPASSWD rules detected" "none" "none" "No action" "CIS 5.2.4"
  fi

  if grep -REn '^[^#].*ALL[[:space:]]*=[[:space:]]*\(.*\)[[:space:]]*ALL' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -q '\*'; then
    record_finding "Sudo Wildcards" "WARN" "MEDIUM" \
      "Wildcard command specifications present" "see sudoers" "Least privilege" \
      "Replace wildcards with explicit commands" "CIS 5.2"
  fi

  local f
  for f in /etc/sudoers /etc/sudoers.d/*; do
    [[ -f "$f" ]] || continue
    [[ "$(basename "$f")" == "README" ]] && continue
    if is_world_writable "$f"; then
      record_finding "Sudo Writable Config" "FAIL" "CRITICAL" \
        "Sudo configuration is world-writable" "$f" "not writable by others" \
        "chmod 0440 ${f}" "CIS 5.2.1"
    fi
  done
}

module_sudo_plan() {
  printf '  Audit sudoers and sudoers.d\n'
  printf '  Repair permissions on sudoers if unsafe\n'
  printf '  Install a Defaults drop-in (use_pty, logfile) after visudo -cf\n'
  printf '  Never write invalid sudoers\n'
}

module_sudo_apply() {
  if [[ -f /etc/sudoers ]]; then
    local mode
    mode="$(file_mode /etc/sudoers || true)"
    if [[ "$mode" != "440" && "$mode" != "400" ]]; then
      backup_file /etc/sudoers sudo
      log_action "chmod 0440 /etc/sudoers"
      if changes_allowed; then
        chown root:root /etc/sudoers
        chmod 0440 /etc/sudoers
      fi
    fi
  fi

  local dropin="/etc/sudoers.d/99-server-hardening"
  local content
  content="$(cat <<'EOF'
Defaults    use_pty
Defaults    logfile="/var/log/sudo.log"
Defaults    loglinelen=0
Defaults    requiretty
EOF
)"
  # requiretty can break some automation; keep it configurable.
  if is_false "${SUDO_REQUIRETTY:-false}"; then
    content="$(printf '%s\n' "$content" | sed '/requiretty/d')"
  fi

  local tmp
  tmp="$(mktemp)"
  printf '%s\n' "$content" > "$tmp"
  chmod 0440 "$tmp"
  if ! validate_sudoers_file "$tmp"; then
    rm -f "$tmp"
    log_error "Generated sudoers drop-in failed visudo -cf; not installed"
    return 1
  fi
  if [[ -f "$dropin" ]] && cmp -s "$tmp" "$dropin"; then
    rm -f "$tmp"
    log_info "Sudo drop-in unchanged"
    return 0
  fi
  backup_file "$dropin" sudo 2>/dev/null || true
  log_action "Install ${dropin}"
  if changes_allowed; then
    cp "$tmp" "$dropin"
    chmod 0440 "$dropin"
    chown root:root "$dropin"
    if ! validate_sudoers_file "$dropin"; then
      log_error "Installed drop-in failed validation; removing"
      rm -f "$dropin"
      rm -f "$tmp"
      return 1
    fi
  fi
  rm -f "$tmp"
}

module_sudo_validate() {
  if [[ -f /etc/sudoers ]]; then
    validate_sudoers_file /etc/sudoers
  fi
  if [[ -f /etc/sudoers.d/99-server-hardening ]]; then
    validate_sudoers_file /etc/sudoers.d/99-server-hardening
  fi
}

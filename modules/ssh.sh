#!/usr/bin/env bash
# SSH hardening via drop-in. Never overwrites /etc/ssh/sshd_config.

SSH_MANAGED_DROPIN="/etc/ssh/sshd_config.d/${SSH_DROPIN_FILE:-99-server-hardening.conf}"

_ssh_config_has_include() {
  [[ -d /etc/ssh/sshd_config.d ]] && \
    grep -qE '^Include[[:space:]]+.*/sshd_config\.d' /etc/ssh/sshd_config 2>/dev/null
}

_ssh_get_effective() {
  local key="$1"
  if have_cmd sshd && sshd -T >/dev/null 2>&1; then
    sshd -T 2>/dev/null | awk -v k="$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]')" \
      '$1 == k {print $2; exit}'
  fi
}

_ssh_build_dropin() {
  local port="${SSH_PORT:-}"
  cat <<EOF
# Managed by Server Hardener. Do not edit; re-run the tool.
# Original sshd_config is left intact.

EOF
  if [[ -n "$port" ]]; then
    printf 'Port %s\n' "$port"
  fi
  if is_true "${SSH_DISABLE_ROOT_LOGIN:-true}"; then
    printf 'PermitRootLogin no\n'
  else
    printf 'PermitRootLogin prohibit-password\n'
  fi
  if is_true "${SSH_DISABLE_PASSWORD_AUTH:-false}"; then
    printf 'PasswordAuthentication no\n'
  fi
  if is_false "${SSH_PERMIT_EMPTY_PASSWORDS:-false}"; then
    printf 'PermitEmptyPasswords no\n'
  fi
  printf 'MaxAuthTries %s\n' "${SSH_MAX_AUTH_TRIES:-3}"
  printf 'LoginGraceTime %s\n' "${SSH_LOGIN_GRACE_TIME:-60}"
  printf 'ClientAliveInterval %s\n' "${SSH_CLIENT_ALIVE_INTERVAL:-300}"
  printf 'ClientAliveCountMax %s\n' "${SSH_CLIENT_ALIVE_COUNT_MAX:-2}"
  printf 'MaxSessions %s\n' "${SSH_MAX_SESSIONS:-4}"
  printf 'MaxStartups %s\n' "${SSH_MAX_STARTUPS:-10:30:60}"
  if is_false "${SSH_X11_FORWARDING:-false}"; then
    printf 'X11Forwarding no\n'
  fi
  if is_false "${SSH_ALLOW_TCP_FORWARDING:-false}"; then
    printf 'AllowTcpForwarding no\n'
  fi
  if is_false "${SSH_ALLOW_AGENT_FORWARDING:-false}"; then
    printf 'AllowAgentForwarding no\n'
  fi
  if is_false "${SSH_PERMIT_TUNNEL:-false}"; then
    printf 'PermitTunnel no\n'
  fi
  if is_true "${SSH_USE_PAM:-true}"; then
    printf 'UsePAM yes\n'
  fi
  if is_false "${SSH_PRINT_MOTD:-false}"; then
    printf 'PrintMotd no\n'
  fi
  if is_true "${SSH_PRINT_LASTLOG:-true}"; then
    printf 'PrintLastLog yes\n'
  fi
  if [[ -n "${SSH_BANNER:-}" ]]; then
    printf 'Banner %s\n' "$SSH_BANNER"
  fi
  if [[ -n "${SSH_ALLOW_USERS:-}" ]]; then
    printf 'AllowUsers %s\n' "${SSH_ALLOW_USERS//,/ }"
  fi
  if [[ -n "${SSH_ALLOW_GROUPS:-}" ]]; then
    printf 'AllowGroups %s\n' "${SSH_ALLOW_GROUPS//,/ }"
  fi
  if [[ -n "${SSH_DENY_USERS:-}" ]]; then
    printf 'DenyUsers %s\n' "${SSH_DENY_USERS//,/ }"
  fi
  if [[ -n "${SSH_DENY_GROUPS:-}" ]]; then
    printf 'DenyGroups %s\n' "${SSH_DENY_GROUPS//,/ }"
  fi
  if is_true "${SSH_HARDEN_ALGORITHMS:-true}"; then
    printf 'KexAlgorithms %s\n' "${SSH_KEX_ALGORITHMS:-curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512}"
    printf 'Ciphers %s\n' "${SSH_CIPHERS:-chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr}"
    printf 'MACs %s\n' "${SSH_MACS:-hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512}"
  fi
}

# Silent predicate. Sets SSH_LOCKOUT_REASON when a lockout is detected.
# Callers log only when they actually abort or warn the administrator.
_ssh_would_lock_current_user() {
  SSH_LOCKOUT_REASON=""
  if [[ "$IS_SSH_SESSION" != "true" ]]; then
    return 1
  fi
  local user="${CURRENT_SSH_USER:-}"
  [[ -z "$user" ]] && return 1

  if [[ -n "${SSH_ALLOW_USERS:-}" ]]; then
    if ! printf '%s\n' ${SSH_ALLOW_USERS//,/ } | grep -qx "$user"; then
      SSH_LOCKOUT_REASON="AllowUsers would exclude the current SSH user (${user})"
      return 0
    fi
  fi
  if [[ -n "${SSH_DENY_USERS:-}" ]]; then
    if printf '%s\n' ${SSH_DENY_USERS//,/ } | grep -qx "$user"; then
      SSH_LOCKOUT_REASON="DenyUsers includes the current SSH user (${user})"
      return 0
    fi
  fi
  if is_true "${SSH_DISABLE_PASSWORD_AUTH:-false}"; then
    local keys="${HOME}/.ssh/authorized_keys"
    if [[ -n "${SUDO_USER:-}" && -f "/home/${SUDO_USER}/.ssh/authorized_keys" ]]; then
      keys="/home/${SUDO_USER}/.ssh/authorized_keys"
    fi
    if [[ ! -s "$keys" ]]; then
      SSH_LOCKOUT_REASON="Password auth would be disabled and no authorized_keys were found for the current user"
      return 0
    fi
  fi
  return 1
}

_ssh_target_port() {
  if [[ -n "${SSH_PORT:-}" ]]; then
    printf '%s' "$SSH_PORT"
  else
    printf '%s' "$SSH_PORT_CURRENT"
  fi
}

module_ssh_audit() {
  if ! have_cmd sshd && [[ ! -f /etc/ssh/sshd_config ]]; then
    record_finding "SSH" "SKIP" "INFO" "sshd not installed" "missing" "OpenSSH server" \
      "Install openssh-server if this host should accept SSH" "CIS 5.1"
    return 0
  fi

  local rootlogin passauth empty
  rootlogin="$(_ssh_get_effective permitrootlogin)"
  passauth="$(_ssh_get_effective passwordauthentication)"
  empty="$(_ssh_get_effective permitemptypasswords)"

  if [[ "$rootlogin" == "no" || "$rootlogin" == "prohibit-password" ]]; then
    record_finding "SSH Root Login" "PASS" "INFO" \
      "Direct root login is restricted" "${rootlogin}" "no or prohibit-password" \
      "No action" "CIS 5.1.1 / NIST IA-2"
  else
    record_finding "SSH Root Login" "WARN" "HIGH" \
      "Root may log in over SSH" "${rootlogin:-unknown}" "no" \
      "Set PermitRootLogin no after confirming a sudo account works" "CIS 5.1.1"
  fi

  if [[ "$empty" == "no" ]]; then
    record_finding "SSH Empty Passwords" "PASS" "INFO" \
      "Empty passwords are rejected" "no" "no" "No action" "CIS 5.1.4"
  else
    record_finding "SSH Empty Passwords" "FAIL" "CRITICAL" \
      "Empty passwords may be permitted" "${empty:-unknown}" "no" \
      "Set PermitEmptyPasswords no" "CIS 5.1.4"
  fi

  if [[ -f "$SSH_MANAGED_DROPIN" ]]; then
    record_finding "SSH Managed Config" "PASS" "INFO" \
      "Hardener drop-in is present" "$SSH_MANAGED_DROPIN" "managed drop-in" \
      "No action" "CIS 5.1"
  else
    record_finding "SSH Managed Config" "WARN" "MEDIUM" \
      "Hardener drop-in is not installed" "absent" "$SSH_MANAGED_DROPIN" \
      "Apply the SSH module" "CIS 5.1"
  fi
}

module_ssh_plan() {
  printf '  Backup /etc/ssh/sshd_config and sshd_config.d\n'
  printf '  Write drop-in %s (sshd_config is not overwritten)\n' "$SSH_MANAGED_DROPIN"
  printf '  Target SSH port: %s (current %s)\n' "$(_ssh_target_port)" "$SSH_PORT_CURRENT"
  printf '  PermitRootLogin=%s  PasswordAuthentication disable=%s\n' \
    "${SSH_DISABLE_ROOT_LOGIN}" "${SSH_DISABLE_PASSWORD_AUTH}"
  printf '  Validate with sshd -t before reload\n'
  if [[ "$IS_SSH_SESSION" == "true" ]]; then
    printf '  %sRemote SSH session — current user %s and port %s will be protected%s\n' \
      "${C_YELLOW}" "${CURRENT_SSH_USER}" "$SSH_PORT_CURRENT" "${C_RESET}"
  fi
}

module_ssh_apply() {
  announce_defense SSH_DISABLE_ROOT_LOGIN "Disable SSH root login"
  announce_defense SSH_DISABLE_PASSWORD_AUTH "Disable SSH password authentication"
  announce_defense SSH_HARDEN_ALGORITHMS "Harden SSH algorithms"
  backup_paths ssh /etc/ssh/sshd_config /etc/ssh/sshd_config.d

  if _ssh_would_lock_current_user; then
    log_error "${SSH_LOCKOUT_REASON}"
    if ! prompt_confirm_dangerous "Proposed SSH settings may lock out the current session. Continue anyway?"; then
      log_error "SSH changes aborted to prevent lockout"
      return 1
    fi
  fi

  local target_port
  target_port="$(_ssh_target_port)"
  if [[ "$IS_SSH_SESSION" == "true" && -n "${SSH_PORT:-}" && "$SSH_PORT" != "$SSH_PORT_CURRENT" ]]; then
    log_warning "SSH port change ${SSH_PORT_CURRENT} -> ${SSH_PORT}. Keep the current port allowed on the firewall until a new session is confirmed."
  fi

  local tmp
  tmp="$(mktemp)"
  _ssh_build_dropin > "$tmp"

  if _ssh_config_has_include; then
    log_action "Install SSH drop-in ${SSH_MANAGED_DROPIN}"
    if changes_allowed; then
      mkdir -p /etc/ssh/sshd_config.d
      if [[ -f "$SSH_MANAGED_DROPIN" ]]; then
        backup_file "$SSH_MANAGED_DROPIN" ssh
      fi
      cp "$tmp" "$SSH_MANAGED_DROPIN"
      chmod 0644 "$SSH_MANAGED_DROPIN"
    fi
  else
    log_action "sshd_config.d Include not detected; appending a marked block to sshd_config"
    local block
    block="$(cat "$tmp")"
    upsert_marked_block /etc/ssh/sshd_config "ssh" ssh "$block"
  fi
  rm -f "$tmp"

  if ! changes_allowed; then
    return 0
  fi

  if ! validate_sshd_config; then
    log_error "sshd -t failed. Restoring SSH configuration."
    if [[ -n "$BACKUP_SESSION" && -f "${BACKUP_SESSION}/meta/files.tsv" ]]; then
      # Restore only ssh module files from this session.
      local src dest
      while IFS=$'\t' read -r _ts module src dest _; do
        [[ "$module" == "ssh" && -e "$dest" ]] || continue
        cp -a "$dest" "$src" 2>/dev/null || true
      done < "${BACKUP_SESSION}/meta/files.tsv"
    fi
    return 1
  fi

  current_ssh_port_protected "$target_port" || true
  svc_reload "$SSH_SERVICE"
}

module_ssh_validate() {
  if have_cmd sshd; then
    validate_sshd_config
  fi
}

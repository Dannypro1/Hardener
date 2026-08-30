#!/usr/bin/env bash
# User defenses. Never deletes accounts. Locks empty-password accounts on apply.

_users_uid0() {
  awk -F: '$3 == 0 { print $1 }' /etc/passwd 2>/dev/null
}

_users_empty_password() {
  if [[ -r /etc/shadow ]]; then
    awk -F: '($2 == "" && $1 != "") { print $1 }' /etc/shadow 2>/dev/null
  fi
}

_users_nologin_shell() {
  if [[ -x /usr/sbin/nologin ]]; then
    printf '/usr/sbin/nologin'
  elif [[ -x /sbin/nologin ]]; then
    printf '/sbin/nologin'
  else
    printf '/bin/false'
  fi
}

# System accounts that should not have a login shell.
_users_locked_system_accounts() {
  printf '%s\n' daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody
}

_users_password_capable() {
  if [[ -r /etc/shadow ]]; then
    awk -F: '($2 != "*" && $2 != "!" && $2 != "!!" && $2 != "") { print $1 }' /etc/shadow 2>/dev/null
  fi
}

_users_is_allowuser() {
  local name="$1"
  [[ -z "${SSH_ALLOW_USERS:-}" ]] && return 1
  printf '%s\n' ${SSH_ALLOW_USERS//,/ } | grep -qx "$name"
}

_users_login_humans() {
  awk -F: '$3 >= 1000 && $1 != "nobody" && $7 !~ /(nologin|false)$/ { print $1 }' /etc/passwd 2>/dev/null
}

module_users_audit() {
  local uid0 empty
  uid0="$(_users_uid0 | tr '\n' ',' | sed 's/,$//')"
  local uid0_count
  uid0_count="$(_users_uid0 | wc -l | tr -d ' ')"

  if [[ "$uid0_count" -gt 1 ]]; then
    record_finding "UID 0 Accounts" "FAIL" "CRITICAL" \
      "Multiple UID 0 accounts exist" \
      "$uid0" \
      "root only" \
      "Review extra UID 0 accounts. This module will not delete them." \
      "CIS 5.4.2 / NIST IA-2"
  else
    record_finding "UID 0 Accounts" "PASS" "INFO" \
      "Single UID 0 account" \
      "${uid0:-root}" \
      "root only" \
      "No action" \
      "CIS 5.4.2"
  fi

  empty="$(_users_empty_password | tr '\n' ',' | sed 's/,$//')"
  if [[ -n "$empty" ]]; then
    record_finding "Empty Passwords" "FAIL" "CRITICAL" \
      "Accounts with empty password hashes" \
      "$empty" \
      "No empty password fields" \
      "Apply this module to lock those accounts" \
      "CIS 5.4.1 / NIST IA-5"
  else
    record_finding "Empty Passwords" "PASS" "INFO" \
      "No empty password hashes (or shadow unreadable)" \
      "none" \
      "none" \
      "No action" \
      "CIS 5.4.1"
  fi

  local pwlog
  pwlog="$(_users_password_capable | tr '\n' ',' | sed 's/,$//')"
  record_finding "Password login accounts" "INFO" "INFO" \
    "Accounts that can authenticate with a password (should match AllowUsers)" \
    "${pwlog:-none}" \
    "${SSH_ALLOW_USERS:-documented allow list}" \
    "Create only AllowUsers; set nologin on other service accounts" \
    "CIS 5.4 / NIST IA-2"

  local shells
  shells="$(grep -vE '/(nologin|false)$' /etc/passwd 2>/dev/null | cut -d: -f1 | tr '\n' ',' | sed 's/,$//')"
  record_finding "Interactive shells" "INFO" "INFO" \
    "Accounts with a real shell" \
    "${shells:-none}" \
    "AllowUsers plus root console only" \
    "usermod -s /usr/sbin/nologin <service_account>" \
    "CIS 5.4.2"

  if [[ -f /etc/profile.d/99-server-hardening-umask.sh ]]; then
    record_finding "User umask" "PASS" "INFO" "Managed umask profile is present" \
      "${USER_UMASK:-027}" "027" "No action" "CIS 5.4.3"
  fi

  local user homedir uid mode
  while IFS=: read -r user _ uid _ _ homedir _; do
    [[ "$uid" -lt 1000 && "$user" != "root" ]] && continue
    [[ -z "$homedir" || "$homedir" == "/" ]] && continue
    if [[ -d "$homedir" ]]; then
      mode="$(file_mode "$homedir" || true)"
      if [[ -n "$mode" && "$mode" -gt 750 ]]; then
        record_finding "Home Permissions" "WARN" "MEDIUM" \
          "Home directory is overly permissive" \
          "${homedir} mode=${mode}" \
          "0750 or stricter" \
          "Apply this module to chmod 0750" \
          "CIS 5.4.2.6"
      fi
    fi
  done < /etc/passwd
}

module_users_plan() {
  printf '  Lock empty-password accounts: %s\n' "${USER_LOCK_EMPTY_PASSWORDS:-true}"
  printf '  Set umask %s: %s\n' "${USER_UMASK:-027}" "${USER_SET_UMASK:-true}"
  printf '  Set TMOUT %s: %s\n' "${USER_TMOUT:-900}" "${USER_SET_TMOUT:-false}"
  printf '  Tighten home directories: %s\n' "${USER_TIGHTEN_HOMES:-false}"
  printf '  nologin on system accounts: %s\n' "${USER_NOLOGIN_SYSTEM:-false}"
  printf '  Ensure SSH users: %s (never copy or log passwords)\n' "${SSH_ENSURE_USERS:-none}"
  printf '  nologin extra humans not in AllowUsers: %s\n' "${USER_NOLOGIN_EXTRA:-false}"
  printf '  Never delete users; share new passwords out of band (not Slack via this tool)\n'
}

_users_lock_account() {
  local acct="$1"
  log_action "Lock empty-password account ${acct}"
  if changes_allowed && have_cmd passwd; then
    passwd -l "$acct" || true
  fi
}

_users_apply_umask_tmout() {
  local umask_val="${USER_UMASK:-027}"
  if is_true "${USER_SET_UMASK:-true}" && [[ -n "$umask_val" ]]; then
    write_managed_file /etc/profile.d/99-server-hardening-umask.sh 0644 users <<EOF
# Managed by Server Hardener
umask ${umask_val}
EOF
    if [[ -f /etc/login.defs ]]; then
      backup_file /etc/login.defs users
      if changes_allowed; then
        if grep -qE '^UMASK[[:space:]]' /etc/login.defs; then
          sed -i -E "s/^UMASK[[:space:]]+.*/UMASK\t${umask_val}/" /etc/login.defs
        else
          printf 'UMASK\t%s\n' "$umask_val" >> /etc/login.defs
        fi
      else
        log_action "Would set UMASK ${umask_val} in login.defs"
      fi
    fi
  fi

  local tmout="${USER_TMOUT:-900}"
  if is_true "${USER_SET_TMOUT:-false}" && [[ "$tmout" != "0" && -n "$tmout" ]]; then
    write_managed_file /etc/profile.d/99-server-hardening-tmout.sh 0644 users <<EOF
# Managed by Server Hardener — idle shell timeout (seconds)
TMOUT=${tmout}
export TMOUT
EOF
  fi
}

_users_nologin_system() {
  local acct shell nologin
  nologin="$(_users_nologin_shell)"
  [[ -f /etc/passwd ]] || return 0
  while IFS= read -r acct; do
    [[ -z "$acct" ]] && continue
    grep -qE "^${acct}:" /etc/passwd || continue
    shell="$(awk -F: -v u="$acct" '$1==u {print $7}' /etc/passwd)"
    case "$shell" in
      /sbin/nologin|/usr/sbin/nologin|/bin/false|/usr/bin/false|"") continue ;;
    esac
    # Only touch well-known system accounts, never human users.
    log_action "Set nologin shell on system account ${acct}"
    if changes_allowed && have_cmd usermod; then
      usermod -s "$nologin" "$acct" || true
    fi
  done < <(_users_locked_system_accounts)
}

_users_set_password() {
  local acct="$1"
  if ! changes_allowed; then
    log_action "Would set password for ${acct} (prompted, not logged)"
    return 0
  fi
  if is_true "$NON_INTERACTIVE"; then
    log_warning "User ${acct} exists or was created; set a password with passwd ${acct} (do not put it in logs or Slack from this tool)"
    return 0
  fi
  log_info "Set a password for ${acct}. It will not be logged. Share it out of band yourself if required."
  passwd "$acct" || log_warning "passwd ${acct} failed or was skipped"
}

_users_ensure_login_account() {
  local name="$1"
  [[ -z "$name" ]] && return 0
  if id "$name" >/dev/null 2>&1; then
    log_info "Login account already exists: ${name}"
  else
    log_action "Create login account ${name} with bash and sudo"
    if changes_allowed; then
      local sudo_grp="sudo"
      getent group sudo >/dev/null 2>&1 || sudo_grp="wheel"
      if is_true "${SSH_ENSURE_SUDO:-true}"; then
        useradd -m -s /bin/bash -G "$sudo_grp" "$name" || useradd -m -s /bin/bash "$name"
      else
        useradd -m -s /bin/bash "$name"
      fi
    fi
  fi
  if id "$name" >/dev/null 2>&1 && is_true "${SSH_ENSURE_SUDO:-true}" && changes_allowed; then
    local sudo_grp="sudo"
    getent group sudo >/dev/null 2>&1 || sudo_grp="wheel"
    usermod -aG "$sudo_grp" "$name" 2>/dev/null || true
  fi
  if id "$name" >/dev/null 2>&1; then
    _users_set_password "$name"
  fi
}

_users_nologin_extra_humans() {
  local nologin acct
  nologin="$(_users_nologin_shell)"
  while IFS= read -r acct; do
    [[ -z "$acct" ]] && continue
    _users_is_allowuser "$acct" && continue
    [[ "$acct" == "${CURRENT_SSH_USER:-}" ]] && continue
    [[ "$acct" == "root" ]] && continue
    if is_true "$NON_INTERACTIVE"; then
      log_action "Set nologin on extra account ${acct}"
      if changes_allowed; then
        usermod -s "$nologin" "$acct" || true
      fi
      continue
    fi
    if prompt_yes_no "Set nologin on '${acct}' (not in AllowUsers; will not delete)?" "n"; then
      log_action "Set nologin on ${acct}"
      if changes_allowed; then
        usermod -s "$nologin" "$acct" || true
      fi
    fi
  done < <(_users_login_humans)
}

module_users_apply() {
  announce_defense USER_LOCK_EMPTY_PASSWORDS "Lock empty-password accounts"
  announce_defense USER_TIGHTEN_HOMES "Tighten home directories to 0750"
  announce_defense USER_SET_UMASK "Set umask ${USER_UMASK:-027}"
  announce_defense USER_SET_TMOUT "Set TMOUT=${USER_TMOUT:-900}"
  announce_defense USER_NOLOGIN_SYSTEM "nologin on known system accounts"
  announce_defense USER_ENSURE_SSH_USERS "Create AllowUsers login accounts"
  announce_defense USER_NOLOGIN_EXTRA "nologin extra humans not in AllowUsers"

  local acct
  while IFS= read -r acct; do
    [[ -z "$acct" ]] && continue
    if is_false "${USER_LOCK_EMPTY_PASSWORDS:-true}"; then
      log_info "Skipped lock of ${acct} (option is off)"
      continue
    fi
    if is_true "$NON_INTERACTIVE"; then
      _users_lock_account "$acct"
    elif prompt_confirm_dangerous "Lock account '${acct}' because it has an empty password?"; then
      _users_lock_account "$acct"
    else
      log_warning "Left empty-password account unchanged: ${acct}"
    fi
  done < <(_users_empty_password)

  if is_true "${USER_TIGHTEN_HOMES:-false}"; then
    local user homedir uid mode
    while IFS=: read -r user _ uid _ _ homedir _; do
      [[ "$uid" -lt 1000 && "$user" != "root" ]] && continue
      [[ -d "$homedir" ]] || continue
      mode="$(file_mode "$homedir" || true)"
      if [[ -n "$mode" && "$mode" -gt 750 ]]; then
        backup_file "$homedir" users
        log_action "chmod 0750 ${homedir}"
        if changes_allowed; then
          chmod 0750 "$homedir"
        fi
      fi
    done < /etc/passwd
  fi

  _users_apply_umask_tmout

  if is_true "${USER_NOLOGIN_SYSTEM:-false}"; then
    _users_nologin_system
  fi

  if is_true "${USER_ENSURE_SSH_USERS:-false}" && [[ -n "${SSH_ENSURE_USERS:-${SSH_ALLOW_USERS:-}}" ]]; then
    local u
    while IFS= read -r u; do
      [[ -z "$u" ]] && continue
      _users_ensure_login_account "$u"
    done < <(split_list "${SSH_ENSURE_USERS:-$SSH_ALLOW_USERS}")
  fi

  if is_true "${USER_NOLOGIN_EXTRA:-false}" && [[ -n "${SSH_ALLOW_USERS:-}" ]]; then
    _users_nologin_extra_humans
  fi
}

module_users_validate() {
  return 0
}

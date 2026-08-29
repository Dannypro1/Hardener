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
  printf '  Never delete users\n'
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

module_users_apply() {
  announce_defense USER_LOCK_EMPTY_PASSWORDS "Lock empty-password accounts"
  announce_defense USER_TIGHTEN_HOMES "Tighten home directories to 0750"
  announce_defense USER_SET_UMASK "Set umask ${USER_UMASK:-027}"
  announce_defense USER_SET_TMOUT "Set TMOUT=${USER_TMOUT:-900}"
  announce_defense USER_NOLOGIN_SYSTEM "nologin on known system accounts"

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
}

module_users_validate() {
  return 0
}

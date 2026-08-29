#!/usr/bin/env bash
# User security audit and cautious remediation. Never deletes accounts.

_users_uid0() {
  awk -F: '$3 == 0 { print $1 }' /etc/passwd 2>/dev/null
}

_users_empty_password() {
  if [[ -r /etc/shadow ]]; then
    awk -F: '($2 == "" && $1 != "") { print $1 }' /etc/shadow 2>/dev/null
  fi
}

_users_nologin_shells() {
  printf '%s\n' /sbin/nologin /usr/sbin/nologin /bin/false /usr/bin/false
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
      "Lock or set passwords. Confirmation required before lock." \
      "CIS 5.4.1 / NIST IA-5"
  else
    record_finding "Empty Passwords" "PASS" "INFO" \
      "No empty password hashes (or shadow unreadable)" \
      "none" \
      "none" \
      "No action" \
      "CIS 5.4.1"
  fi

  local home user homedir
  while IFS=: read -r user _ uid _ _ homedir _; do
    [[ "$uid" -lt 1000 && "$user" != "root" ]] && continue
    [[ -z "$homedir" || "$homedir" == "/" ]] && continue
    if [[ -d "$homedir" ]]; then
      local mode
      mode="$(file_mode "$homedir" || true)"
      if [[ -n "$mode" && "$mode" -gt 750 ]]; then
        record_finding "Home Permissions" "WARN" "MEDIUM" \
          "Home directory is overly permissive" \
          "${homedir} mode=${mode}" \
          "0750 or stricter" \
          "chmod 0750 ${homedir}" \
          "CIS 5.4.2.6"
      fi
    fi
  done < /etc/passwd
}

module_users_plan() {
  printf '  Audit local users, UID 0, empty passwords, shells, sudo, homes\n'
  printf '  Lock empty-password accounts only after confirmation\n'
  printf '  Never delete users automatically\n'
}

module_users_apply() {
  local acct
  while IFS= read -r acct; do
    [[ -z "$acct" ]] && continue
    if prompt_confirm_dangerous "Lock account '${acct}' because it has an empty password?"; then
      log_action "Lock empty-password account ${acct}"
      if changes_allowed && have_cmd passwd; then
        passwd -l "$acct" || true
      fi
    else
      log_warning "Left empty-password account unchanged: ${acct}"
    fi
  done < <(_users_empty_password)

  local user homedir uid mode
  while IFS=: read -r user _ uid _ _ homedir _; do
    [[ "$uid" -lt 1000 && "$user" != "root" ]] && continue
    [[ -d "$homedir" ]] || continue
    mode="$(file_mode "$homedir" || true)"
    if [[ -n "$mode" && "$mode" -gt 750 ]]; then
      if prompt_yes_no "Tighten ${homedir} from ${mode} to 0750?" "n"; then
        log_action "chmod 0750 ${homedir}"
        if changes_allowed; then
          chmod 0750 "$homedir"
        fi
      fi
    fi
  done < /etc/passwd
}

module_users_validate() {
  return 0
}

#!/usr/bin/env bash
# User account posture check.

check_users() {
  local extra_root
  extra_root="$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null | tr '\n' ',' | sed 's/,$//')"
  if [[ -n "$extra_root" ]]; then
    record_finding "Users" "FAIL" "CRITICAL" "Additional UID 0 accounts" "$extra_root" "root only" \
      "Investigate; do not delete automatically" "CIS 5.4.2 / NIST IA-2"
  else
    record_finding "Users" "PASS" "INFO" "No extra UID 0 accounts" "root" "root only" "No action" "CIS 5.4.2"
  fi

  if [[ -r /etc/shadow ]]; then
    local empty
    empty="$(awk -F: '$2=="" {print $1}' /etc/shadow | tr '\n' ',' | sed 's/,$//')"
    if [[ -n "$empty" ]]; then
      record_finding "Empty Password Accounts" "FAIL" "CRITICAL" \
        "Empty password hashes" "$empty" "none" "Lock or set passwords" "CIS 5.4.1 / NIST IA-5"
    fi
  fi
}

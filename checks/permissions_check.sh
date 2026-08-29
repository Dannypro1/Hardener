#!/usr/bin/env bash
# Sensitive path permission check.

check_permissions() {
  local path mode
  for path in /etc/passwd /etc/group; do
    [[ -e "$path" ]] || continue
    mode="$(file_mode "$path")"
    if [[ "$mode" == "644" || "$mode" == "444" ]]; then
      record_finding "Permissions ${path}" "PASS" "INFO" "Expected mode" "$mode" "644" "No action" "CIS 6.1"
    else
      record_finding "Permissions ${path}" "WARN" "MEDIUM" "Unexpected mode" "$mode" "644" \
        "chmod 644 ${path}" "CIS 6.1"
    fi
  done

  if [[ -e /etc/shadow ]]; then
    mode="$(file_mode /etc/shadow)"
    case "$mode" in
      640|600|400)
        record_finding "Permissions /etc/shadow" "PASS" "INFO" "Shadow is restricted" "$mode" "0640/0600" \
          "No action" "CIS 6.1.2"
        ;;
      *)
        record_finding "Permissions /etc/shadow" "FAIL" "HIGH" "Shadow is too open" "$mode" "0640" \
          "chmod 0640 /etc/shadow" "CIS 6.1.2"
        ;;
    esac
  fi
}

#!/usr/bin/env bash
# Listening / risky service check.

check_services() {
  local risky="telnet rsh rlogin rexec ypbind tftp avahi-daemon cups"
  local found=()
  local s
  for s in $risky; do
    if declare -F svc_is_active >/dev/null 2>&1 && svc_is_active "$s"; then
      found+=("$s")
    fi
  done
  if [[ ${#found[@]} -eq 0 ]]; then
    record_finding "Services" "PASS" "INFO" "No high-risk legacy services running" "none" "none" \
      "No action" "CIS 2.2"
  else
    record_finding "Services" "WARN" "MEDIUM" "Legacy or risky services are running" \
      "${found[*]}" "disabled unless required" \
      "Confirm then disable via the services module" "CIS 2.2 / CIS Control 4"
  fi
}

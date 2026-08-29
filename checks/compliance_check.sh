#!/usr/bin/env bash
# High-level OS security rollup for the scored report.

check_compliance() {
  if os_is_supported; then
    record_finding "OS Security" "PASS" "INFO" \
      "Distribution is in the supported set" \
      "${OS_PRETTY:-$OS_ID}" \
      "Ubuntu/Debian/Fedora/CentOS/RHEL/Rocky/AlmaLinux" \
      "Keep the OS on a supported release" \
      "CIS 1.1"
  else
    record_finding "OS Security" "WARN" "HIGH" \
      "Distribution is not officially supported by this tool" \
      "${OS_PRETTY:-unknown}" \
      "A supported distribution" \
      "Review modules manually; package names may differ" \
      "CIS 1.1"
  fi

  if [[ "${INIT_SYSTEM}" == "systemd" ]]; then
    record_finding "Init System" "PASS" "INFO" "systemd detected" "systemd" "systemd" "No action" "CIS 1.2"
  else
    record_finding "Init System" "WARN" "LOW" "Non-systemd init" "${INIT_SYSTEM}" "systemd" \
      "Service enablement may be limited" "CIS 1.2"
  fi
}

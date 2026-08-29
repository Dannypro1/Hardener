#!/usr/bin/env bash
# Wazuh agent presence and service check.

check_wazuh() {
  if have_cmd wazuh-control || [[ -x /var/ossec/bin/wazuh-control ]] || is_package_installed wazuh-agent 2>/dev/null; then
    if declare -F svc_is_active >/dev/null 2>&1 && svc_is_active wazuh-agent; then
      record_finding "Wazuh" "PASS" "INFO" "Agent service is active" "active" "active if required" \
        "Verify manager connectivity" "CIS Control 8"
    else
      record_finding "Wazuh" "WARN" "MEDIUM" "Agent present but not active" "inactive" "active" \
        "systemctl start wazuh-agent after registration" "CIS Control 8"
    fi
  else
    record_finding "Wazuh" "INFO" "INFO" "Wazuh agent not installed" "absent" "optional" \
      "Install only if a manager is available" "CIS Control 8"
  fi
}

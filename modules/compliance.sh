#!/usr/bin/env bash
# Unified compliance pass — sources check scripts and scores the host.

module_compliance_audit() {
  local chk
  for chk in ssh firewall users permissions services pam_mfa wazuh compliance; do
    if [[ -f "${CHECK_DIR}/${chk}_check.sh" ]]; then
      # shellcheck disable=SC1090
      source "${CHECK_DIR}/${chk}_check.sh"
      local fn="check_${chk}"
      if declare -F "$fn" >/dev/null 2>&1; then
        "$fn"
      fi
    fi
  done
}

module_compliance_plan() {
  printf '  Run the unified security audit engine\n'
  printf '  Map findings to CIS / NIST where documented\n'
  printf '  Produce the scored report (zero changes)\n'
}

module_compliance_apply() {
  # Compliance is audit-only by design.
  module_compliance_audit
}

module_compliance_validate() {
  return 0
}

#!/usr/bin/env bash
# =============================================================================
# checks/cve_fix_check.sh
# Check function for CVE remediation module
# =============================================================================

check_cve_fix() {
  local check_script="${HARDENER_ROOT}/cve-fixing/scripts/check_cves.sh"
  if [[ -f "$check_script" ]]; then
    bash "$check_script" || true
  fi
}

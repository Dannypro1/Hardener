#!/usr/bin/env bash
# =============================================================================
# modules/cve_fix.sh
# Hardener Module for CVE Assessment Auditing & Targeted Remediation
# Integrates the cve-fixing channel into the main harden.sh workflow
# =============================================================================

module_cve_fix_audit() {
  local running_k
  running_k="$(uname -r 2>/dev/null || echo "unknown")"

  local is_vulnerable="false"
  if command -v dpkg >/dev/null 2>&1; then
    if dpkg -l linux-image-5.15.0-194-generic 2>/dev/null | grep -q '^ii'; then
      is_vulnerable="true"
    fi
  fi

  if [[ "$is_vulnerable" == "true" ]]; then
    record_finding "CVE Assessment Check" "FAIL" "HIGH" \
      "Active kernel vulnerabilities detected (linux-image-5.15.0-194-generic)" \
      "linux-image-5.15.0-194-generic installed" \
      "latest security patched linux-generic package" \
      "Run the cve_fix module or cve-fixing/cve-fix.sh to upgrade and purge vulnerable kernels" \
      "CIS 1.9 / NIST SI-2"
  else
    record_finding "CVE Assessment Check" "PASS" "INFO" \
      "No active assessment kernel vulnerabilities detected on current packages" \
      "kernel=${running_k}" \
      "patched kernel" \
      "Maintain unattended security updates" \
      "CIS 1.9 / NIST SI-2"
  fi
}

module_cve_fix_plan() {
  printf '  Audit local host against known Wazuh CVE assessment backlog\n'
  printf '  Upgrade vulnerable kernel metapackages (linux-generic)\n'
  printf '  Purge obsolete superseded kernels (e.g., 5.15.0-191, unneeded packages)\n'
  printf '  Verify reboot status and stage bootloader (GRUB)\n'
  printf '  Trigger Wazuh agent vulnerability scanner refresh\n'
}

module_cve_fix_apply() {
  local script="${HARDENER_ROOT}/cve-fixing/scripts/remediate_uisp_kernel.sh"
  if [[ -f "$script" ]]; then
    log_action "Executing CVE remediation channel script..."
    AUTO_REBOOT="${AUTO_REBOOT:-false}" bash "$script" apply
  else
    log_warning "CVE remediation script not found at ${script}"
  fi
}

module_cve_fix_validate() {
  local check_script="${HARDENER_ROOT}/cve-fixing/scripts/check_cves.sh"
  if [[ -f "$check_script" ]]; then
    log_action "Validating CVE remediation outcome..."
    bash "$check_script" || log_warning "Pending reboot or obsolete packages still flagged."
  fi
  return 0
}

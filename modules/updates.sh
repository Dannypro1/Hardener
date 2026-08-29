#!/usr/bin/env bash
# System and security updates. Never reboots unless AUTO_REBOOT=true.

module_updates_audit() {
  local kernel
  kernel="$(uname -r 2>/dev/null || echo unknown)"
  record_finding "System Updates" "INFO" "INFO" \
    "Kernel and package manager detected" \
    "kernel=${kernel} pkg=${PKG_MGR}" \
    "Current security updates applied" \
    "Run this module in apply mode to refresh the index and install updates" \
    "CIS 1.9 / CIS Control 7"

  if os_is_eol; then
    record_finding "OS Lifecycle" "FAIL" "HIGH" \
      "Distribution appears to be end-of-life" \
      "${OS_PRETTY}" \
      "A supported release" \
      "Upgrade the operating system before relying on vendor security updates" \
      "CIS 1.1"
  else
    record_finding "OS Lifecycle" "PASS" "INFO" \
      "OS is treated as supported (best-effort detection)" \
      "${OS_PRETTY}" \
      "Supported release" \
      "Confirm vendor support status for this version" \
      "CIS 1.1"
  fi

  if pending_reboot; then
    record_finding "Pending Reboot" "WARN" "MEDIUM" \
      "A reboot is required to finish updates" \
      "reboot pending" \
      "reboot completed if updates require it" \
      "Schedule a reboot. AUTO_REBOOT remains false unless configured." \
      "CIS Control 7"
  else
    record_finding "Pending Reboot" "PASS" "INFO" \
      "No reboot-required flag detected" \
      "none" \
      "none" \
      "No action" \
      "CIS Control 7"
  fi
}

module_updates_plan() {
  printf '  Refresh package index via %s\n' "$PKG_MGR"
  printf '  Apply security updates\n'
  printf '  Report kernel %s\n' "$(uname -r 2>/dev/null || echo unknown)"
  printf '  Recommend removal of high-risk unused packages (no automatic removal)\n'
  printf '  Never reboot unless AUTO_REBOOT=true (currently %s)\n' "${AUTO_REBOOT:-false}"
}

module_updates_apply() {
  update_package_index
  upgrade_packages true

  local pkg
  for pkg in ${UNNECESSARY_PACKAGES:-}; do
    if is_package_installed "$pkg"; then
      log_warning "Unnecessary package present (not removed): ${pkg}"
    fi
  done

  log_info "Running kernel: $(uname -r 2>/dev/null || echo unknown)"
  if pending_reboot; then
    log_warning "Reboot pending after updates"
  fi
}

module_updates_validate() {
  log_info "Update module complete (pkg=${PKG_MGR})"
  return 0
}

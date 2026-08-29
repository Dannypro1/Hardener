#!/usr/bin/env bash
# Kernel information and conservative module checks. No silent feature removal.

module_kernel_audit() {
  local kver
  kver="$(uname -r 2>/dev/null || echo unknown)"
  record_finding "Kernel Version" "INFO" "INFO" \
    "Running kernel" "$kver" "Vendor-supported kernel" \
    "Apply updates via the updates module" "CIS 1.9"

  if [[ -r /proc/sys/kernel/dmesg_restrict ]]; then
    local v
    v="$(cat /proc/sys/kernel/dmesg_restrict)"
    if [[ "$v" == "1" ]]; then
      record_finding "dmesg_restrict" "PASS" "INFO" "dmesg restricted" "1" "1" "No action" "CIS 1.5.1"
    else
      record_finding "dmesg_restrict" "WARN" "LOW" "dmesg is unrestricted" "$v" "1" \
        "Set kernel.dmesg_restrict=1 via the sysctl module" "CIS 1.5.1"
    fi
  fi

  if [[ -r /proc/sys/kernel/kptr_restrict ]]; then
    local v
    v="$(cat /proc/sys/kernel/kptr_restrict)"
    if [[ "$v" -ge 1 ]]; then
      record_finding "kptr_restrict" "PASS" "INFO" "kernel pointers restricted" "$v" ">=1" "No action" "CIS 1.5.2"
    else
      record_finding "kptr_restrict" "WARN" "LOW" "kernel pointers exposed" "$v" "1 or 2" \
        "Set kernel.kptr_restrict=1 via sysctl" "CIS 1.5.2"
    fi
  fi

  # Rarely needed protocols — report only.
  local mod
  for mod in dccp sctp rds tipc; do
    if lsmod 2>/dev/null | awk '{print $1}' | grep -qx "$mod"; then
      record_finding "Kernel module ${mod}" "WARN" "LOW" \
        "Uncommon network protocol module is loaded" "loaded" "unloaded unless required" \
        "Blacklist only with a documented reason" "CIS 3.2"
    fi
  done
}

module_kernel_plan() {
  printf '  Report kernel version and key security knobs\n'
  printf '  Optionally blacklist uncommon protocols (dccp sctp rds tipc) if confirmed\n'
  printf '  Does not disable modules without a documented reason\n'
}

module_kernel_apply() {
  if is_true "${KERNEL_BLACKLIST_UNCOMMON:-false}"; then
    local file="/etc/modprobe.d/99-server-hardening.conf"
    local content
    content="$(cat <<'EOF'
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF
)"
    write_managed_file "$file" 0644 kernel <<<"$content"
  else
    log_info "Kernel uncommon-protocol blacklist skipped (KERNEL_BLACKLIST_UNCOMMON=false)"
  fi
}

module_kernel_validate() {
  return 0
}

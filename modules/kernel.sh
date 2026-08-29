#!/usr/bin/env bash
# Kernel defenses: module blacklist, core-dump disable, ASLR / suid_dumpable.

KERNEL_BLACKLIST_UNCOMMON="${KERNEL_BLACKLIST_UNCOMMON:-true}"
KERNEL_BLACKLIST_USB="${KERNEL_BLACKLIST_USB:-false}"
KERNEL_MODPROBE_FILE="/etc/modprobe.d/99-server-hardening.conf"
KERNEL_LIMITS_FILE="/etc/security/limits.d/99-server-hardening-coredump.conf"
KERNEL_SYSCTL_FILE="/etc/sysctl.d/98-server-hardening-kernel.conf"

_kernel_uncommon_net() {
  printf '%s\n' dccp sctp rds tipc
}

_kernel_uncommon_fs() {
  printf '%s\n' cramfs freevxfs jffs2 hfs hfsplus udf
}

_kernel_modprobe_content() {
  local mod
  printf '# Managed by Server Hardener — unused protocols and filesystems\n'
  while IFS= read -r mod; do
    printf 'install %s /bin/true\n' "$mod"
    printf 'blacklist %s\n' "$mod"
  done < <(_kernel_uncommon_net; _kernel_uncommon_fs)
  if is_true "${KERNEL_BLACKLIST_USB:-false}"; then
    printf 'install usb-storage /bin/true\n'
    printf 'blacklist usb-storage\n'
  fi
}

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
        "Applied by this module via ${KERNEL_SYSCTL_FILE}" "CIS 1.5.1"
    fi
  fi

  if [[ -r /proc/sys/kernel/kptr_restrict ]]; then
    local v
    v="$(cat /proc/sys/kernel/kptr_restrict)"
    if [[ "$v" -ge 1 ]]; then
      record_finding "kptr_restrict" "PASS" "INFO" "kernel pointers restricted" "$v" ">=1" "No action" "CIS 1.5.2"
    else
      record_finding "kptr_restrict" "WARN" "LOW" "kernel pointers exposed" "$v" "1 or 2" \
        "Applied by this module via ${KERNEL_SYSCTL_FILE}" "CIS 1.5.2"
    fi
  fi

  if [[ -f "$KERNEL_MODPROBE_FILE" ]]; then
    record_finding "Module Blacklist" "PASS" "INFO" "Managed modprobe blacklist present" \
      "$KERNEL_MODPROBE_FILE" "present" "No action" "CIS 3.2"
  else
    record_finding "Module Blacklist" "WARN" "LOW" "Unused protocol/filesystem modules not blacklisted" \
      "absent" "$KERNEL_MODPROBE_FILE" "Apply the kernel module" "CIS 3.2"
  fi

  local mod
  for mod in $(_kernel_uncommon_net); do
    if lsmod 2>/dev/null | awk '{print $1}' | grep -qx "$mod"; then
      record_finding "Kernel module ${mod}" "WARN" "LOW" \
        "Uncommon network protocol module is loaded" "loaded" "blacklisted" \
        "Blacklist is written; unload requires a reboot" "CIS 3.2"
    fi
  done
}

module_kernel_plan() {
  printf '  Write %s (dccp/sctp/rds/tipc + uncommon filesystems)\n' "$KERNEL_MODPROBE_FILE"
  printf '  USB storage blacklist: %s\n' "${KERNEL_BLACKLIST_USB:-false}"
  printf '  Disable core dumps via limits.d and fs.suid_dumpable=0\n'
  printf '  Enforce ASLR (kernel.randomize_va_space=2)\n'
}

module_kernel_apply() {
  announce_defense KERNEL_BLACKLIST_UNCOMMON "Blacklist unused network/FS modules"
  announce_defense KERNEL_BLACKLIST_USB "Blacklist USB storage"

  if is_true "${KERNEL_BLACKLIST_UNCOMMON:-true}"; then
    write_managed_file "$KERNEL_MODPROBE_FILE" 0644 kernel < <(_kernel_modprobe_content)
  fi

  write_managed_file "$KERNEL_LIMITS_FILE" 0644 kernel <<'EOF'
# Managed by Server Hardener — disable core dumps
* hard core 0
* soft core 0
EOF

  write_managed_file "$KERNEL_SYSCTL_FILE" 0644 kernel <<'EOF'
# Managed by Server Hardener — kernel process/memory defenses
kernel.randomize_va_space = 2
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.kexec_load_disabled = 1
fs.suid_dumpable = 0
EOF

  if changes_allowed && have_cmd sysctl; then
    sysctl --system >/dev/null 2>&1 || sysctl -p "$KERNEL_SYSCTL_FILE" >/dev/null 2>&1 || true
  else
    log_action "Would apply kernel sysctl"
  fi
}

module_kernel_validate() {
  return 0
}

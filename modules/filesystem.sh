#!/usr/bin/env bash
# Filesystem / mount hardening. Mount options are recommended, not forced.

_fs_mount_opts() {
  local mp="$1"
  findmnt -n -o OPTIONS "$mp" 2>/dev/null || true
}

_fs_check_mount() {
  local mp="$1"
  shift
  local want=("$@")
  local opts
  opts="$(_fs_mount_opts "$mp")"
  if [[ -z "$opts" ]]; then
    record_finding "Mount ${mp}" "SKIP" "INFO" \
      "Mount point not present or not a separate mount" \
      "not mounted" "separate mount with hardened options where compatible" \
      "Do not remount blindly; application compatibility can break" \
      "CIS 1.1"
    return 0
  fi
  local missing=()
  local o
  for o in "${want[@]}"; do
    if ! printf '%s' "$opts" | grep -qw "$o"; then
      missing+=("$o")
    fi
  done
  if [[ ${#missing[@]} -eq 0 ]]; then
    record_finding "Mount ${mp}" "PASS" "INFO" \
      "Recommended options are present" "$opts" "${want[*]}" "No action" "CIS 1.1"
  else
    record_finding "Mount ${mp}" "WARN" "MEDIUM" \
      "Recommended mount options are missing" \
      "$opts" \
      "${want[*]}" \
      "Consider remount/fstab options (${missing[*]}) only after testing workloads" \
      "CIS 1.1"
  fi
}

module_filesystem_audit() {
  _fs_check_mount /tmp nodev nosuid noexec
  _fs_check_mount /var/tmp nodev nosuid noexec
  _fs_check_mount /home nodev nosuid
  _fs_check_mount /var nodev
  _fs_check_mount /boot nodev nosuid
  if findmnt /dev/shm >/dev/null 2>&1; then
    _fs_check_mount /dev/shm nodev nosuid noexec
  fi
}

module_filesystem_plan() {
  printf '  Audit mount options on /tmp /var/tmp /home /var /boot /dev/shm\n'
  printf '  Recommendations only — fstab is not rewritten automatically\n'
  printf '  noexec on /tmp can break package scripts and installers\n'
}

module_filesystem_apply() {
  log_info "Filesystem module is audit/recommend only. No fstab changes were applied."
  log_info "Apply mount options manually after validating application compatibility."
}

module_filesystem_validate() {
  return 0
}

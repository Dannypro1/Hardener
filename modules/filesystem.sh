#!/usr/bin/env bash
# Filesystem defenses: sticky /tmp, hardened /dev/shm, conservative remounts.

_fs_mount_opts() {
  local mp="$1"
  findmnt -n -o OPTIONS "$mp" 2>/dev/null || true
}

_fs_is_separate_mount() {
  local mp="$1"
  findmnt -n "$mp" >/dev/null 2>&1
}

_fs_has_opt() {
  local opts="$1"
  local want="$2"
  printf '%s' "$opts" | grep -qw "$want"
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
      "Apply this module to harden /dev/shm and sticky /tmp even without a split mount" \
      "CIS 1.1"
    return 0
  fi
  local missing=()
  local o
  for o in "${want[@]}"; do
    if ! _fs_has_opt "$opts" "$o"; then
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
      "This module remounts /dev/shm and applies nodev,nosuid on split /tmp /home" \
      "CIS 1.1"
  fi
}

_fs_sticky_ok() {
  local path="$1"
  [[ -d "$path" && -k "$path" ]]
}

module_filesystem_audit() {
  _fs_check_mount /tmp nodev nosuid
  _fs_check_mount /var/tmp nodev nosuid
  _fs_check_mount /home nodev nosuid
  _fs_check_mount /var nodev
  _fs_check_mount /boot nodev nosuid
  if _fs_is_separate_mount /dev/shm; then
    _fs_check_mount /dev/shm nodev nosuid noexec
  fi

  local p
  for p in /tmp /var/tmp; do
    if [[ -d "$p" ]]; then
      if _fs_sticky_ok "$p"; then
        record_finding "Sticky ${p}" "PASS" "INFO" "Sticky bit is set" "$(file_mode "$p")" "1777" \
          "No action" "CIS 1.1.2"
      else
        record_finding "Sticky ${p}" "FAIL" "HIGH" "Sticky bit missing" "$(file_mode "$p")" "1777" \
          "chmod 1777 ${p}" "CIS 1.1.2"
      fi
    fi
  done
}

module_filesystem_plan() {
  printf '  Enforce sticky bit 1777 on /tmp and /var/tmp\n'
  printf '  Remount /dev/shm with nodev,nosuid,noexec and persist in fstab\n'
  printf '  Remount split /tmp /var/tmp /home with nodev,nosuid\n'
  printf '  noexec on /tmp only if FS_TMP_NOEXEC=true (currently %s)\n' "${FS_TMP_NOEXEC:-false}"
}

_fs_ensure_sticky() {
  local path="$1"
  [[ -d "$path" ]] || return 0
  if _fs_sticky_ok "$path"; then
    log_info "Sticky bit already set on ${path}"
    return 0
  fi
  backup_file "$path" filesystem
  log_action "chmod 1777 ${path}"
  if changes_allowed; then
    chmod 1777 "$path"
  fi
}

_fs_remount() {
  local mp="$1"
  local extra="$2"
  _fs_is_separate_mount "$mp" || return 0
  local cur
  cur="$(_fs_mount_opts "$mp")"
  local need=0
  local o
  for o in ${extra//,/ }; do
    _fs_has_opt "$cur" "$o" || need=1
  done
  (( need == 0 )) && return 0
  log_action "mount -o remount,${extra} ${mp}"
  if changes_allowed; then
    mount -o "remount,${extra}" "$mp" || log_warning "Remount ${mp} failed; fstab entry still written if applicable"
  fi
}

_fs_persist_shm() {
  local line="tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0"
  if [[ -f /etc/fstab ]] && grep -qE '[[:space:]]/dev/shm[[:space:]]' /etc/fstab; then
    if grep -E '[[:space:]]/dev/shm[[:space:]]' /etc/fstab | grep -q 'noexec'; then
      return 0
    fi
    backup_file /etc/fstab filesystem
    log_action "Add nodev,nosuid,noexec to existing /dev/shm fstab entry"
    if changes_allowed; then
      sed -i -E '/[[:space:]]\/dev\/shm[[:space:]]/ s/(defaults|tmpfs)/defaults,nodev,nosuid,noexec/' /etc/fstab || true
    fi
    return 0
  fi
  if [[ -f /etc/fstab ]]; then
    upsert_marked_block /etc/fstab "shm" filesystem "$line"
  fi
}

module_filesystem_apply() {
  if is_true "${FS_HARDEN_TMP_STICKY:-true}"; then
    _fs_ensure_sticky /tmp
    _fs_ensure_sticky /var/tmp
    write_managed_file /etc/tmpfiles.d/99-server-hardening.conf 0644 filesystem <<'EOF'
# Managed by Server Hardener
d /tmp 1777 root root -
d /var/tmp 1777 root root -
EOF
  fi

  if is_true "${FS_HARDEN_SHM:-true}"; then
    _fs_remount /dev/shm "nodev,nosuid,noexec"
    _fs_persist_shm
  fi

  local tmp_opts="nodev,nosuid"
  if is_true "${FS_TMP_NOEXEC:-false}"; then
    tmp_opts="nodev,nosuid,noexec"
  fi
  _fs_remount /tmp "$tmp_opts"
  _fs_remount /var/tmp "$tmp_opts"
  _fs_remount /home "nodev,nosuid"
}

module_filesystem_validate() {
  local p
  for p in /tmp /var/tmp; do
    if [[ -d "$p" ]] && ! _fs_sticky_ok "$p" && changes_allowed; then
      log_warning "${p} sticky bit not set after apply"
    fi
  done
  return 0
}

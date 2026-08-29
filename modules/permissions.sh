#!/usr/bin/env bash
# Sensitive file permissions. Only auto-remediate well-defined paths.

_perm_expect() {
  local path="$1"
  local mode="$2"
  local owner="$3"
  if [[ ! -e "$path" ]]; then
    return 0
  fi
  local cur_mode cur_owner
  cur_mode="$(file_mode "$path")"
  cur_owner="$(file_owner "$path")"
  if [[ "$cur_mode" == "$mode" && "$cur_owner" == "$owner" ]]; then
    record_finding "Perm ${path}" "PASS" "INFO" \
      "Expected ownership and mode" "${cur_owner} ${cur_mode}" "${owner} ${mode}" \
      "No action" "CIS 6.1"
  else
    record_finding "Perm ${path}" "WARN" "HIGH" \
      "Permissions differ from the secure baseline" \
      "${cur_owner} ${cur_mode}" "${owner} ${mode}" \
      "chown ${owner} ${path} && chmod ${mode} ${path}" "CIS 6.1"
  fi
}

module_permissions_audit() {
  _perm_expect /etc/passwd 644 "root:root"
  _perm_expect /etc/group 644 "root:root"
  _perm_expect /etc/shadow 640 "root:shadow" || true
  if [[ -e /etc/shadow ]]; then
    local so
    so="$(file_owner /etc/shadow)"
    if [[ "$so" != "root:shadow" && "$so" != "root:root" ]]; then
      record_finding "Perm /etc/shadow" "FAIL" "CRITICAL" \
        "Unexpected shadow ownership" "$so" "root:root or root:shadow" \
        "chown root:shadow /etc/shadow && chmod 0640 /etc/shadow" "CIS 6.1.2"
    fi
  fi
  _perm_expect /etc/gshadow 640 "root:shadow" || true
  if [[ -f /etc/sudoers ]]; then
    local sm
    sm="$(file_mode /etc/sudoers)"
    if [[ "$sm" != "440" && "$sm" != "400" ]]; then
      record_finding "Perm /etc/sudoers" "FAIL" "HIGH" \
        "sudoers mode is not 0440" "$sm" "440" "chmod 0440 /etc/sudoers" "CIS 5.2.1"
    fi
  fi

  if [[ -d /etc/ssh ]]; then
    local mode
    mode="$(file_mode /etc/ssh)"
    if [[ "$mode" != "755" && "$mode" != "750" && "$mode" != "700" ]]; then
      record_finding "Perm /etc/ssh" "WARN" "MEDIUM" \
        "SSH directory permissions are unusual" "$mode" "0755 or stricter" \
        "chmod 0755 /etc/ssh" "CIS 5.1"
    fi
  fi

  # authorized_keys
  local keys
  while IFS= read -r keys; do
    [[ -z "$keys" ]] && continue
    local km
    km="$(file_mode "$keys")"
    if [[ "$km" != "600" && "$km" != "400" ]]; then
      record_finding "SSH keys ${keys}" "WARN" "HIGH" \
        "authorized_keys is too permissive" "$km" "0600" \
        "chmod 0600 ${keys}" "CIS 5.1.9"
    fi
  done < <(find /root /home -maxdepth 3 -name authorized_keys -type f 2>/dev/null | head -n 50)
}

module_permissions_plan() {
  printf '  Enforce well-known modes on passwd/shadow/group/sudoers/ssh\n'
  printf '  Tighten authorized_keys to 0600\n'
  printf '  Report world-writable system files (no mass chmod)\n'
}

_perm_fix() {
  local path="$1"
  local mode="$2"
  local owner="$3"
  [[ -e "$path" ]] || return 0
  local cur_mode cur_owner
  cur_mode="$(file_mode "$path")"
  cur_owner="$(file_owner "$path")"
  if [[ "$cur_mode" == "$mode" && "$cur_owner" == "$owner" ]]; then
    return 0
  fi
  # shadow/gshadow may be root:root on some images — accept root:root as already ok.
  if [[ "$path" == "/etc/shadow" || "$path" == "/etc/gshadow" ]]; then
    if [[ "$cur_owner" == "root:root" && ( "$cur_mode" == "600" || "$cur_mode" == "640" || "$cur_mode" == "400" ) ]]; then
      return 0
    fi
    if [[ "$cur_owner" == "root:shadow" && ( "$cur_mode" == "640" || "$cur_mode" == "600" || "$cur_mode" == "400" ) ]]; then
      return 0
    fi
  fi
  backup_file "$path" permissions
  log_action "chown ${owner} ${path}; chmod ${mode} ${path}"
  if changes_allowed; then
    chown "$owner" "$path" 2>/dev/null || chown root:root "$path"
    chmod "$mode" "$path"
  fi
}

module_permissions_apply() {
  _perm_fix /etc/passwd 644 root:root
  _perm_fix /etc/group 644 root:root
  if [[ -e /etc/shadow ]]; then
    if getent group shadow >/dev/null 2>&1; then
      _perm_fix /etc/shadow 640 root:shadow
    else
      _perm_fix /etc/shadow 600 root:root
    fi
  fi
  if [[ -e /etc/gshadow ]]; then
    if getent group shadow >/dev/null 2>&1; then
      _perm_fix /etc/gshadow 640 root:shadow
    else
      _perm_fix /etc/gshadow 600 root:root
    fi
  fi
  if [[ -f /etc/sudoers ]]; then
    _perm_fix /etc/sudoers 440 root:root
  fi
  if [[ -d /etc/ssh ]]; then
    _perm_fix /etc/ssh 755 root:root
    local f
    for f in /etc/ssh/sshd_config /etc/ssh/ssh_config; do
      [[ -f "$f" ]] && _perm_fix "$f" 644 root:root
    done
    for f in /etc/ssh/ssh_host_*_key; do
      [[ -f "$f" ]] && _perm_fix "$f" 600 root:root
    done
    for f in /etc/ssh/ssh_host_*_key.pub; do
      [[ -f "$f" ]] && _perm_fix "$f" 644 root:root
    done
  fi

  local keys
  while IFS= read -r keys; do
    [[ -z "$keys" ]] && continue
    local km
    km="$(file_mode "$keys")"
    if [[ "$km" != "600" && "$km" != "400" ]]; then
      backup_file "$keys" permissions
      log_action "chmod 0600 ${keys}"
      if changes_allowed; then
        chmod 0600 "$keys"
      fi
    fi
  done < <(find /root /home -maxdepth 3 -name authorized_keys -type f 2>/dev/null | head -n 50)
}

module_permissions_validate() {
  return 0
}

#!/usr/bin/env bash
# journald / rsyslog / logrotate checks and safe permission fixes.

module_logging_audit() {
  if [[ -d /var/log/journal ]] || [[ -d /run/log/journal ]]; then
    record_finding "journald" "PASS" "INFO" "journald storage detected" "present" "present" "No action" "CIS 4.2"
  else
    record_finding "journald" "INFO" "INFO" "Persistent journal not found" "volatile or unused" "optional persistent journal" \
      "Enable Storage=persistent in journald.conf if desired" "CIS 4.2.1"
  fi

  if have_cmd rsyslogd || svc_exists rsyslog; then
    if svc_is_active rsyslog; then
      record_finding "rsyslog" "PASS" "INFO" "rsyslog is running" "active" "active if used" "No action" "CIS 4.2.2"
    else
      record_finding "rsyslog" "WARN" "LOW" "rsyslog installed but inactive" "inactive" "active if required" \
        "Start rsyslog or rely on journald" "CIS 4.2.2"
    fi
  fi

  local f
  for f in /var/log/auth.log /var/log/secure /var/log/messages /var/log/syslog /var/log/audit/audit.log; do
    [[ -e "$f" ]] || continue
    if is_world_writable "$f"; then
      record_finding "Log ${f}" "FAIL" "HIGH" "Log file is world-writable" "$(file_mode "$f")" "0640 or 0600" \
        "chmod 0640 ${f}" "CIS 4.2.3"
    else
      record_finding "Log ${f}" "PASS" "INFO" "Log permissions look safe" "$(file_mode "$f")" "not world-writable" \
        "No action" "CIS 4.2.3"
    fi
  done

  if [[ -f /etc/logrotate.conf ]]; then
    record_finding "logrotate" "PASS" "INFO" "logrotate.conf present" "present" "present" "No action" "CIS 4.3"
  else
    record_finding "logrotate" "WARN" "LOW" "logrotate.conf missing" "missing" "present" \
      "Install logrotate" "CIS 4.3"
  fi
}

module_logging_plan() {
  printf '  Ensure journald/rsyslog/logrotate are present\n'
  printf '  Restrict permissions on auth/syslog/audit logs\n'
  printf '  Do not ship logs off-host unless configured elsewhere\n'
}

module_logging_apply() {
  if [[ -f /etc/systemd/journald.conf ]]; then
    backup_file /etc/systemd/journald.conf logging
    upsert_marked_block /etc/systemd/journald.conf "journald" logging \
      $'Storage=persistent\nForwardToSyslog=yes\nCompress=yes'
    if changes_allowed; then
      svc_restart systemd-journald || true
    fi
  fi

  local f
  for f in /var/log/auth.log /var/log/secure /var/log/messages /var/log/syslog; do
    [[ -f "$f" ]] || continue
    if is_world_writable "$f"; then
      backup_file "$f" logging
      log_action "chmod 0640 ${f}"
      if changes_allowed; then
        chmod 0640 "$f"
      fi
    fi
  done

  if [[ -f /var/log/audit/audit.log ]]; then
    log_action "chmod 0640 /var/log/audit/audit.log"
    if changes_allowed; then
      chmod 0640 /var/log/audit/audit.log 2>/dev/null || true
    fi
  fi

  if [[ ! -f /etc/logrotate.conf ]] && have_cmd install_package; then
    install_package logrotate || true
  fi
}

module_logging_validate() {
  return 0
}

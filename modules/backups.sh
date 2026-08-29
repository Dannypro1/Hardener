#!/usr/bin/env bash
# Backup housekeeping module (local config snapshots already handled in lib/).

module_backups_audit() {
  local count
  count="$(list_backup_sessions | wc -l | tr -d ' ')"
  record_finding "Hardener Backups" "INFO" "INFO" \
    "Local hardening backup sessions" \
    "count=${count} dir=${BACKUP_DIR}" \
    "Retention ${BACKUP_RETENTION:-10}" \
    "Use --rollback to restore a session" \
    "CIS Control 11"
}

module_backups_plan() {
  printf '  Ensure %s exists and prune sessions beyond BACKUP_RETENTION=%s\n' \
    "$BACKUP_DIR" "${BACKUP_RETENTION:-10}"
}

module_backups_apply() {
  ensure_dir "$BACKUP_DIR" 0750
  prune_old_backups
}

module_backups_validate() {
  [[ -d "$BACKUP_DIR" ]]
}

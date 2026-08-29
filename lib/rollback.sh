#!/usr/bin/env bash
# Restore files from a backup session. Does not delete unrelated admin changes.

rollback_list() {
  local sessions
  mapfile -t sessions < <(list_backup_sessions)
  if [[ ${#sessions[@]} -eq 0 ]]; then
    printf 'No backup sessions found in %s\n' "$BACKUP_DIR"
    return 1
  fi
  printf 'Available backup sessions:\n\n'
  local i=1
  local s
  for s in "${sessions[@]}"; do
    local meta="${BACKUP_DIR}/${s}/meta/session.json"
    local desc="$s"
    if [[ -f "$meta" ]]; then
      desc="${s}  $(tr '\n' ' ' < "$meta" | sed 's/  */ /g')"
    fi
    printf '[%d] %s\n' "$i" "$desc"
    i=$((i + 1))
  done
  printf '\n'
}

rollback_session() {
  local session_id="$1"
  local session="${BACKUP_DIR}/${session_id}"
  if [[ ! -d "$session" ]]; then
    die "Backup session not found: ${session_id}"
  fi
  if ! is_root; then
    die "Rollback requires root"
  fi

  local meta="${session}/meta/files.tsv"
  if [[ ! -f "$meta" ]]; then
    die "Backup metadata missing: ${meta}"
  fi

  log_rollback "Restoring session ${session_id}"
  local ts module src dest name
  while IFS=$'\t' read -r ts module src dest name; do
    [[ -z "$src" || -z "$dest" ]] && continue
    if [[ ! -e "$dest" ]]; then
      log_warning "Backup copy missing, skip: ${dest}"
      continue
    fi
    log_rollback "Restore ${src} from ${dest}"
    if is_dry_run; then
      continue
    fi
    mkdir -p "$(dirname "$src")"
    if [[ -d "$dest" ]]; then
      mkdir -p "$src"
      cp -a "$dest/." "$src/"
    else
      cp -a "$dest" "$src"
    fi
  done < "$meta"

  # Re-validate critical services after restore.
  if have_cmd sshd; then
    if ! validate_sshd_config; then
      log_error "Restored SSH configuration failed sshd -t. Inspect immediately."
    else
      if declare -F svc_reload >/dev/null 2>&1; then
        svc_reload "${SSH_SERVICE:-sshd}" || true
      fi
    fi
  fi

  if have_cmd sysctl && [[ -f /etc/sysctl.d/99-server-hardening.conf ]]; then
    sysctl --system >/dev/null 2>&1 || true
  fi

  log_success "Rollback of ${session_id} completed"
}

rollback_interactive() {
  local sessions
  mapfile -t sessions < <(list_backup_sessions)
  if [[ ${#sessions[@]} -eq 0 ]]; then
    die "No backups available"
  fi
  if is_true "$NON_INTERACTIVE"; then
    rollback_session "${sessions[-1]}"
    return 0
  fi
  rollback_list || true
  local max="${#sessions[@]}"
  local choice
  choice="$(prompt_choice "Select session to restore" 1 "$max" "$max")"
  local idx=$((choice - 1))
  if ! prompt_yes_no "Restore ${sessions[$idx]}? This overwrites managed files" "n"; then
    die "Rollback cancelled" 0
  fi
  rollback_session "${sessions[$idx]}"
}

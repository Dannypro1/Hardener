#!/usr/bin/env bash
# Timestamped configuration backups with metadata for rollback.

backup_session_init() {
  if [[ -n "$BACKUP_SESSION" && -d "$BACKUP_SESSION" ]]; then
    return 0
  fi
  BACKUP_SESSION="${BACKUP_DIR}/${RUN_ID}"
  if is_audit_mode; then
    return 0
  fi
  mkdir -p "${BACKUP_SESSION}/meta"
  chmod 0750 "$BACKUP_SESSION"
  cat > "${BACKUP_SESSION}/meta/session.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "started": "$(iso_timestamp)",
  "os": "${OS_PRETTY:-$OS_NAME}",
  "os_id": "${OS_ID}",
  "mode": "${MODE}",
  "profile": "${PROFILE_NAME_SELECTED}",
  "modules": "${SELECTED_MODULES[*]}",
  "ssh_session": "${IS_SSH_SESSION}",
  "ssh_port": "${SSH_PORT_CURRENT}"
}
EOF
  log_info "Backup session: ${BACKUP_SESSION}"
}

backup_file() {
  local src="$1"
  local module="${2:-misc}"
  local dest_name="${3:-}"

  if [[ ! -e "$src" ]]; then
    log_info "Skip backup (missing): ${src}"
    return 0
  fi

  backup_session_init
  local dest_dir="${BACKUP_SESSION}/${module}"
  mkdir -p "$dest_dir"
  if [[ -z "$dest_name" ]]; then
    dest_name="$(printf '%s' "$src" | sed 's#^/##' | tr '/' '_')"
  fi
  local dest="${dest_dir}/${dest_name}"

  if is_dry_run || is_audit_mode; then
    log_action "Would backup ${src} -> ${dest}"
    return 0
  fi

  if [[ -d "$src" ]]; then
    mkdir -p "$dest"
    cp -a "$src/." "$dest/"
  else
    cp -a "$src" "$dest"
  fi

  local meta="${BACKUP_SESSION}/meta/files.tsv"
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "$(iso_timestamp)" "$module" "$src" "$dest" "${dest_name}" >> "$meta"
  log_info "Backed up ${src}"
}

backup_paths() {
  local module="$1"
  shift
  local path
  for path in "$@"; do
    backup_file "$path" "$module"
  done
}

prune_old_backups() {
  local keep="${BACKUP_RETENTION:-10}"
  [[ -d "$BACKUP_DIR" ]] || return 0
  mapfile -t sessions < <(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort)
  local count="${#sessions[@]}"
  if (( count <= keep )); then
    return 0
  fi
  local remove=$((count - keep))
  local i
  for ((i = 0; i < remove; i++)); do
    log_info "Pruning old backup: ${sessions[$i]}"
    if changes_allowed; then
      rm -rf "${BACKUP_DIR}/${sessions[$i]}"
    fi
  done
}

list_backup_sessions() {
  find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort
}

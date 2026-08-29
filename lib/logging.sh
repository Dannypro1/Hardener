#!/usr/bin/env bash
# Structured logging. Never write secrets, tokens, or private keys.

: "${LOG_FILE:=}"

_log_write() {
  local level="$1"
  shift
  local msg
  msg="$(redact_secrets "$*")"
  local ts
  ts="$(date +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo unknown)"
  local line="[${ts}] [${level}] ${msg}"

  if [[ -n "$LOG_FILE" ]]; then
    printf '%s\n' "$line" >> "$LOG_FILE" 2>/dev/null || true
  fi

  case "$level" in
    ERROR)    printf '%s  ✕  %s%s\n' "${C_RED}"    "$msg" "${C_RESET}" >&2 ;;
    WARNING)  printf '%s  !  %s%s\n' "${C_YELLOW}" "$msg" "${C_RESET}" ;;
    SUCCESS)  printf '%s  ✓  %s%s\n' "${C_BGREEN}" "$msg" "${C_RESET}" ;;
    CHANGE)   printf '%s  →  %s%s\n' "${C_LGREEN}" "$msg" "${C_RESET}" ;;
    ROLLBACK) printf '%s  ↺  %s%s\n' "${C_YELLOW}" "$msg" "${C_RESET}" ;;
    AUDIT)    printf '%s  ▸  %s%s\n' "${C_GREEN}"  "$msg" "${C_RESET}" ;;
    DRY-RUN)  printf '%s  ·  %s%s\n' "${C_DIM}"    "$msg" "${C_RESET}" ;;
    *)        printf '%s  ·  %s%s\n' "${C_GREEN}"  "$msg" "${C_RESET}" ;;
  esac
}

log_info()     { _log_write INFO "$*"; }
log_warning()  { _log_write WARNING "$*"; }
log_error()    { _log_write ERROR "$*"; }
log_success()  { _log_write SUCCESS "$*"; }
log_change()   { _log_write CHANGE "$*"; }
log_rollback() { _log_write ROLLBACK "$*"; }
log_audit()    { _log_write AUDIT "$*"; }
log_debug()    { [[ "${HARDENER_DEBUG:-}" == "1" ]] && _log_write DEBUG "$*" || true; }

log_action() {
  # Describe a mutation. In dry-run / audit, print only.
  local msg="$*"
  if is_audit_mode; then
    _log_write AUDIT "$msg"
    return 0
  fi
  if is_dry_run; then
    _log_write DRY-RUN "$msg"
    return 0
  fi
  log_change "$msg"
}

#!/usr/bin/env bash
# Shared paths, modes, helpers. Sourced by harden.sh before other libraries.
# shellcheck disable=SC2034

HARDENER_VERSION="1.0.1"
HARDENER_NAME="Linux Server Hardener"
HARDENER_AUTHOR="Danny"
HARDENER_AUTHOR_EMAIL="danny.hategekimana@trac.africa"

: "${HARDENER_ROOT:?HARDENER_ROOT must be set before sourcing common.sh}"

CONFIG_DIR="${HARDENER_ROOT}/config"
LIB_DIR="${HARDENER_ROOT}/lib"
MODULE_DIR="${HARDENER_ROOT}/modules"
PROFILE_DIR="${HARDENER_ROOT}/profiles"
CHECK_DIR="${HARDENER_ROOT}/checks"
REPORT_DIR="${HARDENER_ROOT}/reports"
LOG_DIR="${HARDENER_ROOT}/logs"
BACKUP_DIR="${HARDENER_ROOT}/backups"

# Modes: interactive (default), audit, dry-run, apply, rollback, report
MODE="${MODE:-interactive}"
NON_INTERACTIVE="${NON_INTERACTIVE:-false}"
PROFILE_NAME_SELECTED="${PROFILE_NAME_SELECTED:-}"
SELECTED_MODULES=()
BACKUP_SESSION=""
LOG_FILE=""
REPORT_FILE=""
RUN_ID=""

# OS facts (populated by os_detection.sh)
OS_ID=""
OS_ID_LIKE=""
OS_VERSION_ID=""
OS_NAME=""
OS_PRETTY=""
OS_ARCH=""
PKG_MGR=""
INIT_SYSTEM=""
FIREWALL_BACKEND_DETECTED=""
SSH_SERVICE=""
SSH_PORT_CURRENT="22"
IS_SSH_SESSION="false"
CURRENT_SSH_USER=""
CURRENT_SSH_TTY=""

# Runtime flags
CONFIRMED_OS="false"
PLAN_CONFIRMED="false"

# Compliance findings (newline-separated records)
FINDINGS_FILE=""
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

SUPPORTED_OS_IDS="ubuntu debian fedora centos rhel rocky almalinux"

MODULE_CATALOG=(
  "updates:System Updates"
  "users:User Security"
  "passwords:Password Policy"
  "sudo:Sudo Security"
  "ssh:SSH Hardening"
  "pam_mfa:PAM MFA"
  "firewall:Firewall"
  "services:Service Hardening"
  "filesystem:Filesystem Security"
  "permissions:File Permissions"
  "kernel:Kernel Hardening"
  "sysctl:Sysctl Hardening"
  "auditd:Auditd"
  "logging:Logging"
  "fail2ban:Fail2ban"
  "time_sync:Time Synchronization"
  "network:Network Hardening"
  "integrity:File Integrity Monitoring"
  "wazuh:Wazuh Integration"
  "compliance:Compliance Audit"
)

# -----------------------------------------------------------------------------
# Terminal helpers
# -----------------------------------------------------------------------------

hardener_is_tty() {
  [[ -t 0 && -t 1 ]]
}

if hardener_is_tty && [[ -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_DIM=$'\033[2m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_BGREEN=$'\033[1;32m'
  C_LGREEN=$'\033[92m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_CYAN=$'\033[36m'
  C_WHITE=$'\033[37m'
else
  C_RESET="" C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_BGREEN="" C_LGREEN=""
  C_YELLOW="" C_BLUE="" C_CYAN="" C_WHITE=""
fi

# Green box layout (inner width is the number of ═ characters).
UI_WIDTH=56
UI_RULE="════════════════════════════════════════════════════════"
UI_DASH="────────────────────────────────────────────────────────"

die() {
  local msg="${1:-fatal error}"
  local code="${2:-1}"
  if declare -F log_error >/dev/null 2>&1; then
    log_error "$msg"
  else
    printf '%sERROR:%s %s\n' "${C_RED}" "${C_RESET}" "$msg" >&2
  fi
  exit "$code"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

is_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]]
}

is_true() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

is_false() {
  ! is_true "${1:-}"
}

is_audit_mode() {
  [[ "$MODE" == "audit" ]]
}

is_dry_run() {
  [[ "$MODE" == "dry-run" ]]
}

is_apply_mode() {
  [[ "$MODE" == "apply" || "$MODE" == "interactive" ]]
}

changes_allowed() {
  [[ "$MODE" == "apply" || "$MODE" == "interactive" ]] && ! is_dry_run
}

trim() {
  local s="${1:-}"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

# Split comma/space separated lists into lines.
split_list() {
  local raw="${1:-}"
  raw="${raw//,/ }"
  # shellcheck disable=SC2086
  printf '%s\n' $raw | sed '/^$/d'
}

in_list() {
  local needle="$1"
  local item
  shift
  for item in "$@"; do
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

timestamp() {
  date +"%Y-%m-%d_%H%M%S" 2>/dev/null || date +"%Y%m%d%H%M%S"
}

iso_timestamp() {
  date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date
}

ensure_dir() {
  local dir="$1"
  local mode="${2:-0750}"
  if [[ ! -d "$dir" ]]; then
    if changes_allowed || [[ "$dir" == "$LOG_DIR" || "$dir" == "$REPORT_DIR" || "$dir" == "$BACKUP_DIR" ]]; then
      mkdir -p "$dir"
      chmod "$mode" "$dir" 2>/dev/null || true
    fi
  fi
}

# Source a config file if it exists. Values are exported so modules see them.
load_config_file() {
  local file="$1"
  if [[ -f "$file" ]]; then
    # shellcheck disable=SC1090
    set -a
    source "$file"
    set +a
  fi
}

load_all_config() {
  load_config_file "${CONFIG_DIR}/hardening.conf"
  load_config_file "${CONFIG_DIR}/ssh.conf"
  load_config_file "${CONFIG_DIR}/firewall.conf"
  load_config_file "${CONFIG_DIR}/mfa.conf"
  load_config_file "${CONFIG_DIR}/wazuh.conf"
  load_config_file "${CONFIG_DIR}/auditd.conf"
  load_config_file "${CONFIG_DIR}/defense.conf"
}

load_profile() {
  local name="$1"
  local file="${PROFILE_DIR}/${name}.conf"
  if [[ ! -f "$file" ]]; then
    die "Unknown profile: ${name} (expected ${file})"
  fi
  load_config_file "$file"
  PROFILE_NAME_SELECTED="$name"
}

module_label() {
  local id="$1"
  local entry
  for entry in "${MODULE_CATALOG[@]}"; do
    if [[ "${entry%%:*}" == "$id" ]]; then
      printf '%s' "${entry#*:}"
      return 0
    fi
  done
  printf '%s' "$id"
}

is_known_module() {
  local id="$1"
  local entry
  for entry in "${MODULE_CATALOG[@]}"; do
    [[ "${entry%%:*}" == "$id" ]] && return 0
  done
  return 1
}

parse_module_selection() {
  local raw="$1"
  local token
  SELECTED_MODULES=()
  if [[ "$raw" == "all" || "$raw" == "ALL" || "$raw" == "21" ]]; then
    for entry in "${MODULE_CATALOG[@]}"; do
      SELECTED_MODULES+=("${entry%%:*}")
    done
    return 0
  fi
  while IFS= read -r token; do
    token="$(trim "$token")"
    [[ -z "$token" ]] && continue
    if [[ "$token" =~ ^[0-9]+$ ]]; then
      local idx=$((token - 1))
      if (( idx >= 0 && idx < ${#MODULE_CATALOG[@]} )); then
        SELECTED_MODULES+=("${MODULE_CATALOG[$idx]%%:*}")
        continue
      fi
      die "Invalid module number: ${token}"
    fi
    if is_known_module "$token"; then
      SELECTED_MODULES+=("$token")
    else
      die "Unknown module: ${token}"
    fi
  done < <(split_list "$raw")
}

set_modules_from_profile() {
  if [[ -z "${PROFILE_MODULES:-}" ]]; then
    die "Profile ${PROFILE_NAME_SELECTED} does not define PROFILE_MODULES"
  fi
  parse_module_selection "$PROFILE_MODULES"
}

require_root_for_changes() {
  if is_audit_mode; then
    return 0
  fi
  if is_dry_run; then
    return 0
  fi
  if ! is_root; then
    die "Modifications require root. Re-run with sudo, or use --audit / --dry-run."
  fi
}

ui_pad() {
  local text="$1"
  local width="$2"
  local len=${#text}
  if (( len >= width )); then
    printf '%s' "${text:0:width}"
    return 0
  fi
  printf '%s%*s' "$text" $((width - len)) ''
}

ui_box_top() {
  printf '%s╔%s╗%s\n' "${C_GREEN}" "$UI_RULE" "${C_RESET}"
}

ui_box_bottom() {
  printf '%s╚%s╝%s\n' "${C_GREEN}" "$UI_RULE" "${C_RESET}"
}

ui_box_sep() {
  printf '%s╠%s╣%s\n' "${C_GREEN}" "$UI_RULE" "${C_RESET}"
}

ui_box_row() {
  local text="${1:-}"
  printf '%s║%s %s%s%s║%s\n' \
    "${C_GREEN}" "${C_RESET}" "$(ui_pad "$text" $((UI_WIDTH - 1)))" "${C_RESET}" "${C_GREEN}" "${C_RESET}"
}

ui_box_center() {
  local text="$1"
  local inner=$((UI_WIDTH - 1))
  local len=${#text}
  if (( len >= inner )); then
    ui_box_row "$text"
    return 0
  fi
  local left=$(( (inner - len) / 2 ))
  local right=$(( inner - len - left ))
  printf '%s║%s%*s%s%s%s%*s%s║%s\n' \
    "${C_GREEN}" "${C_RESET}" "$left" '' "${C_BGREEN}" "$text" "${C_RESET}" "$right" '' "${C_GREEN}" "${C_RESET}"
}

ui_box_kv() {
  local key="$1"
  local val="$2"
  ui_box_row "$(printf '%-18s %s' "$key" "$val")"
}

ui_section() {
  local title="$1"
  local fill=$((UI_WIDTH - ${#title} - 4))
  (( fill < 4 )) && fill=4
  printf '\n%s┌─ %s %s%s\n' "${C_GREEN}" "$title" "${UI_DASH:0:fill}" "${C_RESET}"
}

ui_section_end() {
  printf '%s└%s%s\n' "${C_GREEN}" "${UI_DASH:0:UI_WIDTH}" "${C_RESET}"
}

ui_menu_item() {
  local num="$1"
  local label="$2"
  printf '  %s[%2s]%s  %s\n' "${C_BGREEN}" "$num" "${C_RESET}" "$label"
}

ui_prompt_mark() {
  printf '%s❯%s ' "${C_BGREEN}" "${C_RESET}"
}

print_banner() {
  printf '\n'
  printf '%s' "${C_BGREEN}"
  cat <<'EOF'
 ██╗     ██╗███╗   ██╗██╗   ██╗██╗  ██╗
 ██║     ██║████╗  ██║██║   ██║╚██╗██╔╝
 ██║     ██║██╔██╗ ██║██║   ██║ ╚███╔╝
 ██║     ██║██║╚██╗██║██║   ██║ ██╔██╗
 ███████╗██║██║ ╚████║╚██████╔╝██╔╝ ██╗
 ╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝
 ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗
 ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
 ███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝
 ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗
 ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║
 ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
 ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██████╗
 ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██╔══██╗
 ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║█████╗  ██████╔╝
 ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║██╔══╝  ██╔══██╗
 ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║███████╗██║  ██║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
EOF
  printf '%s' "${C_GREEN}"
  printf '  ────────────────────────────────────────────────────────────────────────\n'
  printf '  LINUX SERVER HARDENER   v%s   audit · harden · report\n' "${HARDENER_VERSION}"
  printf '  Author: %s  <%s>\n' "${HARDENER_AUTHOR}" "${HARDENER_AUTHOR_EMAIL}"
  printf '  ────────────────────────────────────────────────────────────────────────\n'
  printf '%s\n' "${C_RESET}"
}

print_banner_compact() {
  printf '\n%s' "${C_BGREEN}"
  cat <<'EOF'
 ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██████╗
 ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██╔══██╗
 ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║█████╗  ██████╔╝
 ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║██╔══╝  ██╔══██╗
 ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║███████╗██║  ██║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
EOF
  printf '%s  LINUX SERVER HARDENER  ·  v%s  ·  %s <%s>%s\n\n' \
    "${C_GREEN}" "${HARDENER_VERSION}" "${HARDENER_AUTHOR}" "${HARDENER_AUTHOR_EMAIL}" "${C_RESET}"
}

# Redact known secret-like tokens from strings before logging.
redact_secrets() {
  local line="$1"
  line="$(printf '%s' "$line" | sed -E \
    -e 's/(password|passwd|secret|token|key|registration_password)[[:space:]]*[=:][[:space:]]*[^[:space:]]+/\1=***REDACTED***/Ig' \
    -e 's/(Authorization:[[:space:]]*)[^[:space:]]+/\1***REDACTED***/I')"
  printf '%s' "$line"
}

cleanup_on_exit() {
  local status=$?
  if (( status != 0 )); then
    if declare -F log_error >/dev/null 2>&1; then
      log_error "Exiting with status ${status}"
    fi
  fi
}

install_traps() {
  trap cleanup_on_exit EXIT
  trap 'die "Interrupted" 130' INT
  trap 'die "Terminated" 143' TERM
}

init_run() {
  RUN_ID="$(timestamp)"
  ensure_dir "$LOG_DIR" 0750
  ensure_dir "$REPORT_DIR" 0750
  ensure_dir "$BACKUP_DIR" 0750
  LOG_FILE="${LOG_DIR}/hardening-${RUN_ID}.log"
  FINDINGS_FILE="${REPORT_DIR}/findings-${RUN_ID}.tsv"
  REPORT_FILE="${REPORT_DIR}/report-${RUN_ID}.txt"
  : > "$FINDINGS_FILE"
  install_traps
}

# Write a managed file only when content differs. Backs up the original.
# Usage: write_managed_file DEST MODE MODULE <<'EOF' ... EOF
write_managed_file() {
  local dest="$1"
  local mode="${2:-0644}"
  local module="${3:-misc}"
  local tmp
  tmp="$(mktemp)"
  cat > "$tmp"
  if [[ -f "$dest" ]] && cmp -s "$tmp" "$dest"; then
    rm -f "$tmp"
    log_info "Unchanged: ${dest}"
    return 0
  fi
  if [[ -e "$dest" ]]; then
    backup_file "$dest" "$module"
  fi
  log_action "Write managed file ${dest}"
  if ! changes_allowed; then
    rm -f "$tmp"
    return 0
  fi
  mkdir -p "$(dirname "$dest")"
  cp "$tmp" "$dest"
  chmod "$mode" "$dest"
  rm -f "$tmp"
}

# Insert or replace a marked block inside an existing file (never wholesale overwrite).
# Markers: # BEGIN server-hardener:<tag>  ...  # END server-hardener:<tag>
upsert_marked_block() {
  local dest="$1"
  local tag="$2"
  local module="${3:-misc}"
  local content="$4"
  local begin="# BEGIN server-hardener:${tag}"
  local end="# END server-hardener:${tag}"
  local tmp block
  tmp="$(mktemp)"
  block="$(mktemp)"
  printf '%s\n' "$content" > "$block"

  if [[ -f "$dest" ]]; then
    if grep -qF "$begin" "$dest"; then
      awk -v b="$begin" -v e="$end" -v bf="$block" '
        $0 == b {
          print b
          while ((getline line < bf) > 0) print line
          close(bf)
          print e
          skip=1
          next
        }
        $0 == e { skip=0; next }
        !skip { print }
      ' "$dest" > "$tmp"
    else
      cat "$dest" > "$tmp"
      printf '\n%s\n' "$begin" >> "$tmp"
      cat "$block" >> "$tmp"
      printf '%s\n' "$end" >> "$tmp"
    fi
  else
    printf '%s\n' "$begin" > "$tmp"
    cat "$block" >> "$tmp"
    printf '%s\n' "$end" >> "$tmp"
  fi
  rm -f "$block"

  if [[ -f "$dest" ]] && cmp -s "$tmp" "$dest"; then
    rm -f "$tmp"
    log_info "Unchanged marked block ${tag} in ${dest}"
    return 0
  fi
  if [[ -e "$dest" ]]; then
    backup_file "$dest" "$module"
  fi
  log_action "Update marked block ${tag} in ${dest}"
  if ! changes_allowed; then
    rm -f "$tmp"
    return 0
  fi
  cp "$tmp" "$dest"
  rm -f "$tmp"
}

remove_marked_block() {
  local dest="$1"
  local tag="$2"
  local module="${3:-misc}"
  local begin="# BEGIN server-hardener:${tag}"
  local end="# END server-hardener:${tag}"
  [[ -f "$dest" ]] || return 0
  grep -qF "$begin" "$dest" || return 0
  local tmp
  tmp="$(mktemp)"
  awk -v b="$begin" -v e="$end" '
    $0 == b { skip=1; next }
    $0 == e { skip=0; next }
    !skip { print }
  ' "$dest" > "$tmp"
  backup_file "$dest" "$module"
  log_action "Remove marked block ${tag} from ${dest}"
  if changes_allowed; then
    cp "$tmp" "$dest"
  fi
  rm -f "$tmp"
}

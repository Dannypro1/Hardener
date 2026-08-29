#!/usr/bin/env bash
# Linux Server Hardener — main entry point.
set -Eeuo pipefail

HARDENER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export HARDENER_ROOT

# shellcheck source=lib/common.sh
source "${HARDENER_ROOT}/lib/common.sh"
# shellcheck source=lib/logging.sh
source "${HARDENER_ROOT}/lib/logging.sh"
# shellcheck source=lib/os_detection.sh
source "${HARDENER_ROOT}/lib/os_detection.sh"
# shellcheck source=lib/package_manager.sh
source "${HARDENER_ROOT}/lib/package_manager.sh"
# shellcheck source=lib/prompt.sh
source "${HARDENER_ROOT}/lib/prompt.sh"
# shellcheck source=lib/backup.sh
source "${HARDENER_ROOT}/lib/backup.sh"
# shellcheck source=lib/validation.sh
source "${HARDENER_ROOT}/lib/validation.sh"
# shellcheck source=lib/rollback.sh
source "${HARDENER_ROOT}/lib/rollback.sh"
# shellcheck source=lib/service_manager.sh
source "${HARDENER_ROOT}/lib/service_manager.sh"

usage() {
  cat <<'EOF'
Linux Server Hardener

Usage:
  sudo ./harden.sh
  sudo ./harden.sh --audit
  sudo ./harden.sh --dry-run
  sudo ./harden.sh --apply
  sudo ./harden.sh --rollback
  sudo ./harden.sh --report
  sudo ./harden.sh --profile <name>
  sudo ./harden.sh --profile <name> --non-interactive
  sudo ./harden.sh --modules updates,ssh,firewall

Options:
  --audit              Inspect only. Makes zero changes. Root not required.
  --dry-run            Show the exact plan without applying it.
  --apply              Apply selected modules (requires confirmation unless
                       --non-interactive).
  --rollback           Restore a previous backup session.
  --report             Print the most recent audit report.
  --profile NAME       Use a predefined profile: basic, server, web-server,
                       database-server, hardened.
  --modules LIST       Comma-separated module ids or menu numbers.
  --non-interactive    Do not prompt. Uses profile/module defaults.
  --yes                Same as answering yes to the final apply prompt
                       (still refuses dangerous MFA/user-deletion actions).
  -h, --help           Show this help.
  -v, --version        Show version.

Modules:
  updates users passwords sudo ssh pam_mfa firewall services filesystem
  permissions kernel sysctl auditd logging fail2ban time_sync network
  integrity wazuh compliance
EOF
}

parse_args() {
  local modules_arg=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --audit) MODE="audit"; shift ;;
      --dry-run) MODE="dry-run"; shift ;;
      --apply) MODE="apply"; shift ;;
      --rollback) MODE="rollback"; shift ;;
      --report) MODE="report"; shift ;;
      --profile)
        [[ -n "${2:-}" ]] || die "--profile requires a name"
        load_profile "$2"
        shift 2
        ;;
      --modules)
        [[ -n "${2:-}" ]] || die "--modules requires a list"
        modules_arg="$2"
        shift 2
        ;;
      --non-interactive) NON_INTERACTIVE="true"; shift ;;
      --yes) REQUIRE_CONFIRMATION="false"; shift ;;
      -h|--help) print_banner; usage; exit 0 ;;
      -v|--version) print_banner; printf '  %s%s %s%s\n\n' "${C_BGREEN}" "$HARDENER_NAME" "$HARDENER_VERSION" "${C_RESET}"; exit 0 ;;
      *) die "Unknown option: $1" ;;
    esac
  done
  if [[ -n "$modules_arg" ]]; then
    parse_module_selection "$modules_arg"
  fi
}

source_module() {
  local id="$1"
  local file="${MODULE_DIR}/${id}.sh"
  if [[ ! -f "$file" ]]; then
    die "Module file missing: ${file}"
  fi
  # shellcheck disable=SC1090
  source "$file"
}

run_module_hook() {
  local id="$1"
  local hook="$2"
  local fn="module_${id}_${hook}"
  if declare -F "$fn" >/dev/null 2>&1; then
    "$fn"
  else
    log_warning "Module ${id} has no ${hook} hook"
  fi
}

run_check() {
  local id="$1"
  local file="${CHECK_DIR}/${id}_check.sh"
  if [[ -f "$file" ]]; then
    # shellcheck disable=SC1090
    source "$file"
    local fn="check_${id}"
    if declare -F "$fn" >/dev/null 2>&1; then
      "$fn"
    fi
  fi
}

print_plan() {
  printf '\n'
  ui_box_top
  ui_box_center "CONFIGURATION PLAN"
  ui_box_sep
  ui_box_kv "Mode" "$MODE"
  ui_box_kv "Profile" "${PROFILE_NAME_SELECTED:-none}"
  ui_box_kv "Modules" "${SELECTED_MODULES[*]}"
  ui_box_bottom
  local id
  for id in "${SELECTED_MODULES[@]}"; do
    ui_section "$(module_label "$id")"
    run_module_hook "$id" "plan"
    ui_section_end
  done
  printf '\n'
}

run_pre_audit() {
  log_info "Pre-security audit"
  local id
  for id in "${SELECTED_MODULES[@]}"; do
    run_module_hook "$id" "audit"
    case "$id" in
      ssh|firewall|users|permissions|services|pam_mfa|wazuh|compliance)
        run_check "$id"
        ;;
    esac
  done
}

apply_selected_modules() {
  backup_session_init
  local id
  for id in "${SELECTED_MODULES[@]}"; do
    printf '\n'
    ui_box_top
    ui_box_center "APPLY  ·  $(module_label "$id")"
    ui_box_bottom
    run_module_hook "$id" "apply"
    run_module_hook "$id" "validate"
  done
}

run_post_audit() {
  log_info "Post-hardening audit"
  PASS_COUNT=0 WARN_COUNT=0 FAIL_COUNT=0 SKIP_COUNT=0
  CRITICAL_COUNT=0 HIGH_COUNT=0 MEDIUM_COUNT=0 LOW_COUNT=0
  : > "$FINDINGS_FILE"
  local id
  for id in "${SELECTED_MODULES[@]}"; do
    run_module_hook "$id" "audit"
    case "$id" in
      ssh|firewall|users|permissions|services|pam_mfa|wazuh|compliance)
        run_check "$id"
        ;;
    esac
  done
}

main() {
  load_all_config
  parse_args "$@"
  init_run
  log_info "${HARDENER_NAME} ${HARDENER_VERSION} starting (mode=${MODE})"

  if [[ "$MODE" == "report" ]]; then
    show_latest_report
    return 0
  fi

  if [[ "$MODE" == "rollback" ]]; then
    require_root_for_changes
    rollback_interactive
    return 0
  fi

  detect_environment
  confirm_detected_os
  require_root_for_changes

  if [[ -n "$PROFILE_NAME_SELECTED" && ${#SELECTED_MODULES[@]} -eq 0 ]]; then
    set_modules_from_profile
  fi
  select_modules_interactive

  local id
  for id in "${SELECTED_MODULES[@]}"; do
    source_module "$id"
  done

  run_pre_audit
  print_plan
  confirm_plan

  if is_audit_mode; then
    generate_report
    log_success "Audit complete. No changes were made."
    return 0
  fi

  apply_selected_modules
  run_post_audit
  generate_report
  prune_old_backups

  if pending_reboot && is_true "${AUTO_REBOOT:-false}"; then
    log_warning "Reboot required and AUTO_REBOOT=true — rebooting"
    if changes_allowed; then
      shutdown -r +1 "Server Hardener: reboot required"
    fi
  elif pending_reboot; then
    log_warning "A reboot is pending. It will not be performed automatically."
  fi

  log_success "Run complete. Log: ${LOG_FILE}"
}

main "$@"

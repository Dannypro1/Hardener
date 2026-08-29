#!/usr/bin/env bash
# Interactive prompts. Non-interactive mode uses defaults and never blocks.

prompt_read() {
  local message="$1"
  local default="${2:-}"
  local reply=""
  if is_true "$NON_INTERACTIVE"; then
    printf '%s' "$default"
    return 0
  fi
  ui_prompt_mark >&2
  if [[ -n "$default" ]]; then
    printf '%s%s%s [%s]: ' "${C_GREEN}" "$message" "${C_RESET}" "$default" >&2
  else
    printf '%s%s%s: ' "${C_GREEN}" "$message" "${C_RESET}" >&2
  fi
  IFS= read -r reply || true
  if [[ -z "$reply" ]]; then
    printf '%s' "$default"
  else
    printf '%s' "$(trim "$reply")"
  fi
}

prompt_yes_no() {
  local message="$1"
  local default="${2:-n}"
  if is_true "$NON_INTERACTIVE"; then
    is_true "$default" || [[ "$default" == "y" || "$default" == "Y" ]]
    return
  fi
  local hint="y/N"
  [[ "$default" == "y" || "$default" == "Y" ]] && hint="Y/n"
  local reply
  ui_prompt_mark >&2
  printf '%s%s%s [%s]: ' "${C_GREEN}" "$message" "${C_RESET}" "$hint" >&2
  IFS= read -r reply || true
  reply="$(trim "${reply:-$default}")"
  [[ "$reply" == "y" || "$reply" == "Y" || "$reply" == "yes" ]]
}

prompt_choice() {
  local message="$1"
  local min="$2"
  local max="$3"
  local default="${4:-$min}"
  local reply=""
  if is_true "$NON_INTERACTIVE"; then
    printf '%s' "$default"
    return 0
  fi
  while true; do
    ui_prompt_mark >&2
    printf '%s%s%s: ' "${C_GREEN}" "$message" "${C_RESET}" >&2
    IFS= read -r reply || true
    reply="$(trim "$reply")"
    if [[ -z "$reply" ]]; then
      reply="$default"
    fi
    if [[ "$reply" =~ ^[0-9]+$ ]] && (( reply >= min && reply <= max )); then
      printf '%s' "$reply"
      return 0
    fi
    printf 'Enter a number between %s and %s.\n' "$min" "$max" >&2
  done
}

prompt_confirm_dangerous() {
  local message="$1"
  if is_true "$NON_INTERACTIVE"; then
    log_warning "Non-interactive: refusing dangerous change: ${message}"
    return 1
  fi
  printf '\n%sWARNING:%s %s\n' "${C_YELLOW}" "${C_RESET}" "$message"
  prompt_yes_no "Type y to proceed" "n"
}

show_module_menu() {
  print_banner_compact
  ui_box_top
  ui_box_row "OPERATING SYSTEM"
  ui_box_sep
  ui_box_row "  ✓  ${OS_PRETTY:-$OS_NAME}"
  ui_box_bottom
  printf '\n'
  ui_box_top
  ui_box_center "SELECT SECURITY MODULES"
  ui_box_sep
  local i=1
  local mid=10
  local left right
  while (( i <= mid )); do
    local j=$((i + mid))
    left="$(printf '[%2d]  %-20s' "$i" "${MODULE_CATALOG[$((i - 1))]#*:}")"
    if (( j <= ${#MODULE_CATALOG[@]} )); then
      right="$(printf '[%2d]  %s' "$j" "${MODULE_CATALOG[$((j - 1))]#*:}")"
      ui_box_row " ${left}${right}"
    else
      ui_box_row " ${left}"
    fi
    i=$((i + 1))
  done
  ui_box_sep
  ui_box_row " [21]  ALL MODULES"
  ui_box_bottom
  printf '\n%s  Enter numbers, comma-separated  ·  example: 1,5,6,7%s\n' "${C_GREEN}" "${C_RESET}"
}

select_modules_interactive() {
  if [[ -n "${PROFILE_NAME_SELECTED}" ]]; then
    set_modules_from_profile
    log_info "Using profile '${PROFILE_NAME_SELECTED}' modules: ${SELECTED_MODULES[*]}"
    return 0
  fi
  if is_true "$NON_INTERACTIVE"; then
    if [[ ${#SELECTED_MODULES[@]} -eq 0 ]]; then
      load_profile "server"
      set_modules_from_profile
      log_info "Non-interactive default profile 'server'"
    fi
    return 0
  fi
  show_module_menu
  local raw
  raw="$(prompt_read "Selections" "")"
  if [[ -z "$raw" ]]; then
    die "No modules selected"
  fi
  parse_module_selection "$raw"
}

confirm_plan() {
  if is_audit_mode; then
    PLAN_CONFIRMED="true"
    return 0
  fi
  if is_true "$NON_INTERACTIVE"; then
    PLAN_CONFIRMED="true"
    return 0
  fi
  if is_false "${REQUIRE_CONFIRMATION:-true}"; then
    PLAN_CONFIRMED="true"
    return 0
  fi
  printf '\n'
  ui_box_top
  ui_box_center "READY TO APPLY"
  ui_box_sep
  ui_box_row "The plan above will be applied to this host."
  if [[ "$IS_SSH_SESSION" == "true" ]]; then
    ui_box_row "Remote SSH session — port ${SSH_PORT_CURRENT} stays open."
  fi
  ui_box_bottom
  printf '\n'
  if prompt_yes_no "Proceed" "n"; then
    PLAN_CONFIRMED="true"
  else
    die "Administrator cancelled" 0
  fi
}

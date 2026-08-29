#!/usr/bin/env bash
# Validation helpers and the unified finding/report engine.

# record_finding CONTROL STATUS SEVERITY REASON CURRENT EXPECTED REMEDIATION [STANDARD]
# STATUS: PASS | WARN | FAIL | INFO | SKIP
# SEVERITY: CRITICAL | HIGH | MEDIUM | LOW | INFO
record_finding() {
  local control="$1"
  local status="$2"
  local severity="$3"
  local reason="$4"
  local current="$5"
  local expected="$6"
  local remediation="$7"
  local standard="${8:-}"

  # TSV with a rarely used separator for fields that may contain spaces.
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$control" "$status" "$severity" "$reason" "$current" "$expected" "$remediation" "$standard" \
    >> "${FINDINGS_FILE}"

  case "$status" in
    PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
    WARN) WARN_COUNT=$((WARN_COUNT + 1)) ;;
    FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
    SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
  esac
  case "$severity" in
    CRITICAL) CRITICAL_COUNT=$((CRITICAL_COUNT + 1)) ;;
    HIGH) HIGH_COUNT=$((HIGH_COUNT + 1)) ;;
    MEDIUM) MEDIUM_COUNT=$((MEDIUM_COUNT + 1)) ;;
    LOW) LOW_COUNT=$((LOW_COUNT + 1)) ;;
  esac

  log_audit "${control}: ${status} (${severity}) — ${reason}"
}

validate_sshd_config() {
  if ! have_cmd sshd; then
    log_warning "sshd not found; cannot validate SSH configuration"
    return 1
  fi
  if sshd -t 2>/dev/null; then
    log_success "sshd configuration is valid"
    return 0
  fi
  log_error "sshd -t failed"
  sshd -t || true
  return 1
}

validate_sudoers_file() {
  local file="$1"
  if ! have_cmd visudo; then
    log_warning "visudo not found; refusing to treat sudoers as valid"
    return 1
  fi
  if visudo -cf "$file" >/dev/null 2>&1; then
    return 0
  fi
  log_error "visudo validation failed for ${file}"
  visudo -cf "$file" || true
  return 1
}

validate_sysctl_file() {
  local file="$1"
  [[ -f "$file" ]] || return 1
  # Parse key=value lines; reject obviously invalid keys.
  local line key
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    key="${line%%=*}"
    key="$(trim "$key")"
    [[ -z "$key" ]] && continue
    if [[ ! -e "/proc/sys/${key//.//}" ]]; then
      log_warning "sysctl key not present on this kernel: ${key}"
    fi
  done < "$file"
  return 0
}

validate_audit_rules() {
  if have_cmd augenrules; then
    augenrules --check >/dev/null 2>&1 || true
  fi
  if have_cmd auditctl; then
    return 0
  fi
  return 1
}

file_mode() {
  local path="$1"
  if [[ ! -e "$path" ]]; then
    printf ''
    return 1
  fi
  stat -c '%a' "$path" 2>/dev/null || stat -f '%OLp' "$path" 2>/dev/null
}

file_owner() {
  local path="$1"
  stat -c '%U:%G' "$path" 2>/dev/null || stat -f '%Su:%Sg' "$path" 2>/dev/null
}

is_world_writable() {
  local path="$1"
  [[ -e "$path" ]] || return 1
  local mode
  mode="$(file_mode "$path")"
  [[ "${mode: -1}" == "2" || "${mode: -1}" == "3" || "${mode: -1}" == "6" || "${mode: -1}" == "7" ]]
}

port_is_listening() {
  local port="$1"
  if have_cmd ss; then
    ss -lntH 2>/dev/null | awk -v p=":${port}" '$4 ~ p"$" {found=1} END{exit !found}'
    return
  fi
  if have_cmd netstat; then
    netstat -lnt 2>/dev/null | grep -q ":${port} "
    return
  fi
  return 1
}

current_ssh_port_protected() {
  local port="${1:-$SSH_PORT_CURRENT}"
  [[ "$port" =~ ^[0-9]+$ ]] || return 1
  if [[ "$IS_SSH_SESSION" == "true" ]]; then
    log_info "Protecting current SSH port ${port}"
  fi
  return 0
}

compute_security_score() {
  local total=$((PASS_COUNT + WARN_COUNT + FAIL_COUNT))
  if (( total == 0 )); then
    printf '100'
    return 0
  fi
  local score
  score="$(awk -v p="$PASS_COUNT" -v w="$WARN_COUNT" -v f="$FAIL_COUNT" \
    'BEGIN { printf "%d", ((p*1.0 + w*0.5) / (p+w+f)) * 100 }')"
  # Penalize critical/high failures.
  local penalty=$((CRITICAL_COUNT * 15 + HIGH_COUNT * 8))
  score=$((score - penalty))
  if (( score < 0 )); then score=0; fi
  if (( score > 100 )); then score=100; fi
  printf '%s' "$score"
}

status_color() {
  case "$1" in
    PASS) printf '%s' "${C_GREEN}" ;;
    WARN) printf '%s' "${C_YELLOW}" ;;
    FAIL) printf '%s' "${C_RED}" ;;
    *)    printf '%s' "${C_DIM}" ;;
  esac
}

generate_report() {
  local score
  score="$(compute_security_score)"
  {
    printf 'SERVER SECURITY AUDIT\n'
    printf '=====================\n'
    printf 'Host: %s\n' "$(hostname 2>/dev/null || echo unknown)"
    printf 'OS:   %s\n' "${OS_PRETTY:-$OS_NAME}"
    printf 'Date: %s\n' "$(iso_timestamp)"
    printf 'Mode: %s\n' "$MODE"
    if [[ -n "$PROFILE_NAME_SELECTED" ]]; then
      printf 'Profile: %s\n' "$PROFILE_NAME_SELECTED"
    fi
    printf '\n'

    if [[ -f "$FINDINGS_FILE" ]]; then
      local control status severity
      while IFS=$'\t' read -r control status severity _r _c _e _m _s; do
        [[ -z "$control" ]] && continue
        printf '%-24s %s\n' "$control" "$status"
      done < "$FINDINGS_FILE"
    fi

    printf '\n--------------------------------\n'
    printf 'Critical: %s\n' "$CRITICAL_COUNT"
    printf 'High:     %s\n' "$HIGH_COUNT"
    printf 'Medium:   %s\n' "$MEDIUM_COUNT"
    printf 'Low:      %s\n' "$LOW_COUNT"
    printf '\nSecurity Score: %s/100\n' "$score"
    printf '\nFindings\n--------\n'
    if [[ -f "$FINDINGS_FILE" ]]; then
      while IFS=$'\t' read -r control status severity reason current expected remediation standard; do
        [[ -z "$control" ]] && continue
        printf '\n[%s] %s (%s)\n' "$status" "$control" "$severity"
        printf '  Reason:      %s\n' "$reason"
        printf '  Current:     %s\n' "$current"
        printf '  Expected:    %s\n' "$expected"
        printf '  Remediation: %s\n' "$remediation"
        [[ -n "$standard" ]] && printf '  Standard:    %s\n' "$standard"
      done < "$FINDINGS_FILE"
    fi
  } > "$REPORT_FILE"

  printf '\n'
  ui_box_top
  ui_box_center "SERVER SECURITY AUDIT"
  ui_box_sep
  ui_box_kv "Host" "$(hostname 2>/dev/null || echo unknown)"
  ui_box_kv "OS" "${OS_PRETTY:-$OS_NAME}"
  ui_box_kv "Score" "${score}/100"
  ui_box_sep
  if [[ -f "$FINDINGS_FILE" ]]; then
    while IFS=$'\t' read -r control status severity _r _c _e _m _s; do
      [[ -z "$control" ]] && continue
      printf '%s║%s %s  %s%-10s%s%s%s║%s\n' \
        "${C_GREEN}" "${C_RESET}" \
        "$(ui_pad "$control" 32)" \
        "$(status_color "$status")" "$status" "${C_RESET}" \
        "$(ui_pad "" 11)" \
        "${C_GREEN}" "${C_RESET}"
    done < "$FINDINGS_FILE"
  fi
  ui_box_sep
  ui_box_row " Critical ${CRITICAL_COUNT}   High ${HIGH_COUNT}   Medium ${MEDIUM_COUNT}   Low ${LOW_COUNT}"
  ui_box_bottom
  printf '\n%s  Full report:%s  %s\n' "${C_GREEN}" "${C_RESET}" "$REPORT_FILE"
  log_success "Report written to ${REPORT_FILE}"
}

show_latest_report() {
  local latest
  latest="$(ls -1t "${REPORT_DIR}"/report-*.txt 2>/dev/null | head -n1 || true)"
  if [[ -z "$latest" ]]; then
    die "No reports found in ${REPORT_DIR}"
  fi
  cat "$latest"
}

#!/usr/bin/env bash
# Optional PAM TOTP MFA for SSH only. Designed to avoid full lockout.

MFA_PAM_FILE="/etc/pam.d/sshd"
MFA_STATE_DIR="/etc/server-hardener"
MFA_STATE_FILE="${MFA_STATE_DIR}/mfa.state"

_mfa_package_name() {
  case "$(os_family)" in
    debian) printf 'libpam-google-authenticator' ;;
    rhel)   printf 'google-authenticator' ;;
    *)      printf 'libpam-google-authenticator' ;;
  esac
}

_mfa_module_path() {
  local p
  for p in \
    /lib/x86_64-linux-gnu/security/pam_google_authenticator.so \
    /lib/security/pam_google_authenticator.so \
    /usr/lib64/security/pam_google_authenticator.so \
    /usr/lib/security/pam_google_authenticator.so; do
    if [[ -f "$p" ]]; then
      printf '%s' "$p"
      return 0
    fi
  done
  return 1
}

_mfa_installed() {
  is_package_installed "$(_mfa_package_name)" || _mfa_module_path >/dev/null
}

_mfa_configured() {
  [[ -f "$MFA_PAM_FILE" ]] && grep -q 'pam_google_authenticator' "$MFA_PAM_FILE"
}

_mfa_pam_line() {
  # Per-user ~/.google_authenticator — do not point secret= at a shared path.
  local flags=""
  if is_true "${MFA_NULLOK:-true}"; then
    flags="nullok"
  fi
  printf 'auth required pam_google_authenticator.so %s' "$flags"
}

_mfa_write_state() {
  changes_allowed || return 0
  mkdir -p "$MFA_STATE_DIR"
  chmod 0750 "$MFA_STATE_DIR"
  cat > "$MFA_STATE_FILE" <<EOF
MFA_ENABLED=${MFA_ENABLED}
MFA_METHOD=${MFA_METHOD}
MFA_USERS=${MFA_USERS}
MFA_GROUPS=${MFA_GROUPS}
EOF
  chmod 0640 "$MFA_STATE_FILE"
}

module_pam_mfa_audit() {
  local installed="no" configured="no" pam_ok="no"
  _mfa_installed && installed="yes"
  _mfa_configured && configured="yes"
  [[ -f "$MFA_PAM_FILE" ]] && pam_ok="yes"

  if [[ "$configured" == "yes" && "$installed" == "yes" ]]; then
    record_finding "PAM MFA" "PASS" "INFO" \
      "TOTP PAM module is installed and referenced from sshd PAM" \
      "installed=${installed} configured=${configured}" \
      "Valid SSH MFA when intended" \
      "Enroll users with google-authenticator; secrets stay in home directories" \
      "NIST IA-2(1)"
  elif is_true "${MFA_ENABLED:-false}"; then
    record_finding "PAM MFA" "FAIL" "HIGH" \
      "MFA is requested in config but is not fully active" \
      "installed=${installed} configured=${configured} pam=${pam_ok}" \
      "Module installed and sshd PAM integrated" \
      "Run the PAM MFA module and complete enrollment" \
      "NIST IA-2(1)"
  else
    record_finding "PAM MFA" "INFO" "INFO" \
      "MFA is not enabled (optional control)" \
      "installed=${installed} configured=${configured}" \
      "Optional" \
      "Enable only after a console or out-of-band recovery path is confirmed" \
      "NIST IA-2(1)"
  fi

  if [[ -f /etc/pam.d/sshd ]]; then
    local mode
    mode="$(file_mode /etc/pam.d/sshd || echo '?')"
    if [[ "$mode" == "644" || "$mode" == "640" || "$mode" == "600" ]]; then
      record_finding "PAM Permissions" "PASS" "INFO" \
        "sshd PAM file permissions look reasonable" "mode=${mode}" "0644 or stricter" \
        "No action" "CIS 5.3"
    else
      record_finding "PAM Permissions" "WARN" "MEDIUM" \
        "Unexpected permissions on pam.d/sshd" "mode=${mode}" "0644" \
        "chmod 0644 /etc/pam.d/sshd" "CIS 5.3"
    fi
  fi
}

module_pam_mfa_plan() {
  printf '  Optional TOTP MFA for SSH via %s\n' "$(_mfa_package_name)"
  printf '  Users: %s  Groups: %s\n' "${MFA_USERS:-any enrolled}" "${MFA_GROUPS:-}"
  printf '  Never overwrite /etc/pam.d/sshd wholesale\n'
  printf '  Secrets are not generated, stored, or logged by this tool\n'
  printf '  Requires explicit confirmation because of lockout risk\n'
}

_mfa_interactive_menu() {
  if is_true "$NON_INTERACTIVE"; then
    if is_true "${MFA_ENABLED:-false}"; then
      printf '1'
    else
      printf '4'
    fi
    return 0
  fi
  printf '\n'
  ui_box_top
  ui_box_center "PAM MFA"
  ui_box_sep
  if _mfa_configured; then
    ui_box_row "  Status   MFA is configured in PAM"
  else
    ui_box_row "  Status   MFA is currently disabled"
  fi
  ui_box_sep
  ui_box_row " [1]  Configure TOTP MFA"
  ui_box_row " [2]  Configure users/groups"
  ui_box_row " [3]  Disable MFA"
  ui_box_row " [4]  Skip"
  ui_box_bottom
  printf '\n'
  prompt_choice "Choice" 1 4 4
}

_mfa_apply_pam() {
  if [[ ! -f "$MFA_PAM_FILE" ]]; then
    log_error "PAM sshd file missing: ${MFA_PAM_FILE}"
    return 1
  fi
  backup_file "$MFA_PAM_FILE" pam

  local line
  line="$(_mfa_pam_line)"
  # Place authenticator after common-auth / password-auth inclusion when present.
  local block="${line}"
  upsert_marked_block "$MFA_PAM_FILE" "${MFA_PAM_MARKER:-server-hardener-mfa}" pam "$block"
}

_mfa_remove_pam() {
  if [[ -f "$MFA_PAM_FILE" ]]; then
    remove_marked_block "$MFA_PAM_FILE" "${MFA_PAM_MARKER:-server-hardener-mfa}" pam
    if grep -q 'pam_google_authenticator' "$MFA_PAM_FILE" && ! grep -q 'BEGIN server-hardener' "$MFA_PAM_FILE"; then
      log_warning "pam_google_authenticator remains outside the hardener block; not removed automatically"
    fi
  fi
  MFA_ENABLED=false
  _mfa_write_state
}

module_pam_mfa_apply() {
  printf '\n%sKeep a root console or out-of-band recovery session available before enabling MFA.%s\n' \
    "${C_YELLOW}" "${C_RESET}"

  local choice
  choice="$(_mfa_interactive_menu)"
  case "$choice" in
    4)
      log_info "PAM MFA skipped"
      return 0
      ;;
    3)
      if prompt_confirm_dangerous "Disable MFA PAM integration?"; then
        _mfa_remove_pam
      fi
      return 0
      ;;
    2)
      MFA_USERS="$(prompt_read "Comma-separated MFA users" "${MFA_USERS}")"
      MFA_GROUPS="$(prompt_read "Comma-separated MFA groups" "${MFA_GROUPS}")"
      _mfa_write_state
      log_info "MFA user/group selection stored (enrollment is still per-user)"
      if ! prompt_yes_no "Also configure TOTP PAM now?" "n"; then
        return 0
      fi
      ;;
    1) ;;
  esac

  if ! prompt_confirm_dangerous "Enable SSH TOTP MFA? A broken PAM stack can lock all SSH logins."; then
    log_warning "MFA enablement cancelled"
    return 0
  fi

  local pkg
  pkg="$(_mfa_package_name)"
  if ! _mfa_installed; then
    install_package "$pkg" || {
      log_error "Failed to install ${pkg}"
      return 1
    }
  fi

  if ! _mfa_module_path >/dev/null; then
    log_error "pam_google_authenticator.so not found after install; MFA not enabled"
    return 1
  fi

  _mfa_apply_pam
  MFA_ENABLED=true
  _mfa_write_state
  log_success "PAM MFA line installed. Enroll each user with google-authenticator (do not run that here; secrets must not be logged)."
  log_warning "Test a new SSH session before closing the current one."
}

module_pam_mfa_validate() {
  if ! is_true "${MFA_ENABLED:-false}"; then
    return 0
  fi
  if ! _mfa_installed; then
    log_error "MFA package/module missing"
    return 1
  fi
  if ! _mfa_configured; then
    log_error "PAM sshd does not reference pam_google_authenticator — MFA is NOT active"
    return 1
  fi
  if [[ ! -f "$MFA_PAM_FILE" ]]; then
    return 1
  fi
  log_success "MFA configuration validation passed"
  return 0
}

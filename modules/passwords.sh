#!/usr/bin/env bash
# Password aging, quality, and local account lockout after failed attempts.

PW_MINLEN="${PW_MINLEN:-12}"
PW_MAXDAYS="${PW_MAXDAYS:-365}"
PW_MINDAYS="${PW_MINDAYS:-1}"
PW_WARNAGE="${PW_WARNAGE:-14}"
PW_FAILLOCK_DENY="${PW_FAILLOCK_DENY:-5}"
PW_FAILLOCK_UNLOCK="${PW_FAILLOCK_UNLOCK:-900}"
PW_FAILLOCK_INTERVAL="${PW_FAILLOCK_INTERVAL:-900}"

_pw_login_defs_value() {
  local key="$1"
  awk -v k="$key" 'toupper($1)==toupper(k) {print $2; exit}' /etc/login.defs 2>/dev/null
}

_pw_set_login_def() {
  local key="$1"
  local value="$2"
  if grep -qE "^${key}[[:space:]]" /etc/login.defs; then
    sed -i -E "s/^${key}[[:space:]]+.*/${key}\t${value}/" /etc/login.defs
  else
    printf '%s\t%s\n' "$key" "$value" >> /etc/login.defs
  fi
}

module_passwords_audit() {
  local maxdays minlen
  maxdays="$(_pw_login_defs_value PASS_MAX_DAYS)"
  minlen="$(_pw_login_defs_value PASS_MIN_LEN)"

  if [[ -n "$maxdays" && "$maxdays" -gt 0 && "$maxdays" -le 365 ]]; then
    record_finding "Password Aging" "PASS" "INFO" \
      "PASS_MAX_DAYS is within a typical range" \
      "PASS_MAX_DAYS=${maxdays}" \
      "1-365 days depending on policy" \
      "No action" \
      "CIS 5.4.1.1 / NIST IA-5"
  else
    record_finding "Password Aging" "WARN" "MEDIUM" \
      "Password aging is disabled or unusually high" \
      "PASS_MAX_DAYS=${maxdays:-unset}" \
      "Site policy (default suggestion ${PW_MAXDAYS})" \
      "Apply this module to set login.defs aging" \
      "CIS 5.4.1.1"
  fi

  if [[ -n "$minlen" && "$minlen" -ge 8 ]]; then
    record_finding "Password Length" "PASS" "INFO" \
      "Minimum length is set" \
      "PASS_MIN_LEN=${minlen}" \
      ">= 8 (site may require more)" \
      "No action" \
      "CIS 5.3 / NIST IA-5"
  else
    record_finding "Password Length" "WARN" "LOW" \
      "Minimum password length is weak or unset in login.defs" \
      "PASS_MIN_LEN=${minlen:-unset}" \
      ">= ${PW_MINLEN} for local accounts" \
      "Apply this module to configure login.defs and pwquality" \
      "CIS 5.3"
  fi

  if [[ -f /etc/security/faillock.conf ]]; then
    record_finding "Account Lockout" "PASS" "INFO" \
      "faillock.conf is present" \
      "/etc/security/faillock.conf" \
      "deny=${PW_FAILLOCK_DENY}" \
      "No action" \
      "CIS 5.3.2 / NIST AC-7"
  else
    record_finding "Account Lockout" "WARN" "MEDIUM" \
      "Local failed-logon lockout is not configured" \
      "missing faillock.conf" \
      "deny ${PW_FAILLOCK_DENY} / unlock ${PW_FAILLOCK_UNLOCK}s" \
      "Apply this module to write faillock.conf" \
      "CIS 5.3.2"
  fi
}

module_passwords_plan() {
  printf '  Password aging: %s (MAXDAYS=%s)\n' "${PW_APPLY_AGING:-true}" "$PW_MAXDAYS"
  printf '  pwquality: %s (minlen=%s)\n' "${PW_APPLY_QUALITY:-true}" "$PW_MINLEN"
  printf '  faillock: %s (deny=%s unlock=%ss)\n' \
    "${PW_APPLY_FAILLOCK:-true}" "$PW_FAILLOCK_DENY" "$PW_FAILLOCK_UNLOCK"
  printf '  Does not replace enterprise PAM/IdP stacks\n'
}

_pw_install_quality() {
  local pkg
  case "$(os_family)" in
    debian) pkg="$(package_candidate libpam-pwquality libpwquality || true)" ;;
    rhel)   pkg="$(package_candidate libpwquality pam || true)" ;;
  esac
  if [[ -n "${pkg:-}" ]]; then
    install_package "$pkg" || true
  fi
}

_pw_write_pwquality() {
  local dest="/etc/security/pwquality.conf"
  if [[ ! -e "$dest" ]] && ! changes_allowed && ! is_dry_run; then
    return 0
  fi
  if [[ -f "$dest" ]]; then
    backup_file "$dest" passwords
  fi
  write_managed_file "$dest" 0644 passwords <<EOF
# Managed by Server Hardener — local password quality
minlen = ${PW_MINLEN}
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
minclass = ${PW_MINCLASS:-1}
maxrepeat = 3
maxsequence = 3
dictcheck = 1
enforcing = 1
EOF
}

_pw_write_faillock() {
  local dest="/etc/security/faillock.conf"
  if [[ -f "$dest" ]]; then
    backup_file "$dest" passwords
  fi
  write_managed_file "$dest" 0644 passwords <<EOF
# Managed by Server Hardener — local account lockout
deny = ${PW_FAILLOCK_DENY}
unlock_time = ${PW_FAILLOCK_UNLOCK}
fail_interval = ${PW_FAILLOCK_INTERVAL}
silent
EOF
}

module_passwords_apply() {
  announce_defense PW_APPLY_AGING "Password aging in login.defs"
  announce_defense PW_APPLY_QUALITY "pwquality complexity rules"
  announce_defense PW_APPLY_FAILLOCK "faillock after failed logins"

  if is_true "${PW_APPLY_QUALITY:-true}"; then
    _pw_install_quality
    _pw_write_pwquality
  fi

  if is_true "${PW_APPLY_AGING:-true}" && [[ -f /etc/login.defs ]]; then
    backup_file /etc/login.defs passwords
    if changes_allowed; then
      _pw_set_login_def PASS_MAX_DAYS "$PW_MAXDAYS"
      _pw_set_login_def PASS_MIN_DAYS "$PW_MINDAYS"
      _pw_set_login_def PASS_WARN_AGE "$PW_WARNAGE"
      _pw_set_login_def PASS_MIN_LEN "$PW_MINLEN"
      _pw_set_login_def ENCRYPT_METHOD SHA512
    else
      log_action "Would update password aging in /etc/login.defs"
    fi
  fi

  if is_true "${PW_APPLY_FAILLOCK:-true}"; then
    _pw_write_faillock
  fi
}

module_passwords_validate() {
  [[ -f /etc/login.defs ]] || return 0
  return 0
}

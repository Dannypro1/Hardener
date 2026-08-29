#!/usr/bin/env bash
# Password aging and quality. Avoids hard-coded policies that break enterprise IdP.

PW_MINLEN="${PW_MINLEN:-12}"
PW_MAXDAYS="${PW_MAXDAYS:-365}"
PW_MINDAYS="${PW_MINDAYS:-1}"
PW_WARNAGE="${PW_WARNAGE:-14}"

_pw_login_defs_value() {
  local key="$1"
  awk -v k="$key" 'toupper($1)==toupper(k) {print $2; exit}' /etc/login.defs 2>/dev/null
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
      "Set PASS_MAX_DAYS in /etc/login.defs if this host uses local passwords" \
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
      "Configure login.defs and pam_pwquality / pam_pwquality.conf" \
      "CIS 5.3"
  fi

  if [[ -r /etc/security/pwquality.conf ]]; then
    record_finding "pwquality" "PASS" "INFO" \
      "pwquality configuration is present" \
      "/etc/security/pwquality.conf" \
      "Present on hosts using local passwords" \
      "Review minlen and credit settings" \
      "CIS 5.3.1"
  else
    record_finding "pwquality" "INFO" "INFO" \
      "pwquality.conf not found (may use enterprise auth)" \
      "missing" \
      "optional" \
      "Skip if this host is bound to LDAP/AD" \
      "CIS 5.3.1"
  fi
}

module_passwords_plan() {
  printf '  Review /etc/login.defs aging (MAXDAYS=%s MINDDAYS=%s WARN=%s)\n' \
    "$PW_MAXDAYS" "$PW_MINDAYS" "$PW_WARNAGE"
  printf '  Ensure pwquality minlen>=%s when the file exists\n' "$PW_MINLEN"
  printf '  Do not override enterprise PAM/IdP stacks\n'
}

module_passwords_apply() {
  if [[ -f /etc/login.defs ]]; then
    backup_file /etc/login.defs passwords
    if changes_allowed; then
      _pw_set_login_def PASS_MAX_DAYS "$PW_MAXDAYS"
      _pw_set_login_def PASS_MIN_DAYS "$PW_MINDAYS"
      _pw_set_login_def PASS_WARN_AGE "$PW_WARNAGE"
      if grep -q '^PASS_MIN_LEN' /etc/login.defs; then
        _pw_set_login_def PASS_MIN_LEN "$PW_MINLEN"
      fi
    else
      log_action "Would update password aging in /etc/login.defs"
    fi
  fi

  if [[ -f /etc/security/pwquality.conf ]]; then
    backup_file /etc/security/pwquality.conf passwords
    if ! grep -q '^minlen' /etc/security/pwquality.conf; then
      log_action "Set pwquality minlen=${PW_MINLEN}"
      if changes_allowed; then
        printf '\n# server-hardener\nminlen = %s\n' "$PW_MINLEN" >> /etc/security/pwquality.conf
      fi
    fi
  fi
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

module_passwords_validate() {
  [[ -f /etc/login.defs ]] || return 0
  return 0
}

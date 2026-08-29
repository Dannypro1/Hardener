#!/usr/bin/env bash
# PAM / MFA posture. Never claims MFA is active without validation.

check_pam() {
  if [[ ! -f /etc/pam.d/sshd ]]; then
    record_finding "PAM" "SKIP" "INFO" "pam.d/sshd missing" "missing" "present on SSH hosts" \
      "Install OpenSSH server" "CIS 5.3"
    return 0
  fi

  local installed="no" configured="no"
  if [[ -f /lib/x86_64-linux-gnu/security/pam_google_authenticator.so \
     || -f /usr/lib64/security/pam_google_authenticator.so \
     || -f /lib/security/pam_google_authenticator.so ]]; then
    installed="yes"
  fi
  if grep -q 'pam_google_authenticator' /etc/pam.d/sshd; then
    configured="yes"
  fi

  if [[ "$installed" == "yes" && "$configured" == "yes" ]]; then
    record_finding "PAM MFA" "PASS" "INFO" \
      "TOTP module installed and referenced from sshd PAM" \
      "installed+configured" "validated MFA" \
      "Enroll users; keep a console recovery path" "NIST IA-2(1)"
  else
    record_finding "PAM MFA" "INFO" "INFO" \
      "SSH TOTP MFA is not fully configured" \
      "module=${installed} pam=${configured}" \
      "optional" \
      "Enable via the PAM MFA module after confirming recovery access" "NIST IA-2(1)"
  fi
}

check_pam_mfa() {
  check_pam
}

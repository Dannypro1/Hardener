#!/usr/bin/env bash
# Independent SSH posture check used by audit and compliance.

check_ssh() {
  if [[ ! -f /etc/ssh/sshd_config ]]; then
    record_finding "SSH" "SKIP" "INFO" "sshd_config not found" "missing" "OpenSSH installed" \
      "Install openssh-server if SSH is required" "CIS 5.1"
    return 0
  fi

  local root empty tries
  if have_cmd sshd && sshd -T >/dev/null 2>&1; then
    root="$(sshd -T 2>/dev/null | awk '/^permitrootlogin /{print $2}')"
    empty="$(sshd -T 2>/dev/null | awk '/^permitemptypasswords /{print $2}')"
    tries="$(sshd -T 2>/dev/null | awk '/^maxauthtries /{print $2}')"
  else
    root="$(awk '/^[Pp]ermitRootLogin/{print $2; exit}' /etc/ssh/sshd_config)"
    empty="$(awk '/^[Pp]ermitEmptyPasswords/{print $2; exit}' /etc/ssh/sshd_config)"
    tries="$(awk '/^[Mm]axAuthTries/{print $2; exit}' /etc/ssh/sshd_config)"
  fi

  if [[ "$root" == "no" || "$root" == "prohibit-password" ]]; then
    record_finding "SSH Root Login" "PASS" "INFO" "Root login restricted" "${root}" "no" "No action" "CIS 5.1.1"
  else
    record_finding "SSH Root Login" "WARN" "HIGH" "Root login may be permitted" "${root:-default}" "no" \
      "Apply the SSH module or set PermitRootLogin no" "CIS 5.1.1 / NIST IA-2"
  fi

  if [[ "$empty" == "no" ]]; then
    record_finding "SSH Empty Passwords" "PASS" "INFO" "Empty passwords disabled" "no" "no" "No action" "CIS 5.1.4"
  else
    record_finding "SSH Empty Passwords" "FAIL" "CRITICAL" "Empty passwords not explicitly disabled" \
      "${empty:-default}" "no" "Set PermitEmptyPasswords no" "CIS 5.1.4"
  fi

  if [[ -n "$tries" && "$tries" -le 4 ]]; then
    record_finding "SSH MaxAuthTries" "PASS" "INFO" "Auth tries limited" "$tries" "<=4" "No action" "CIS 5.1.6"
  else
    record_finding "SSH MaxAuthTries" "WARN" "LOW" "Auth tries unlimited or high" "${tries:-default}" "3" \
      "Set MaxAuthTries 3" "CIS 5.1.6"
  fi
}

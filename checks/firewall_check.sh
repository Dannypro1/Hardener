#!/usr/bin/env bash
# Firewall posture check.

check_firewall() {
  local backend="${FIREWALL_BACKEND:-$FIREWALL_BACKEND_DETECTED}"
  local sshp="${SSH_PORT_CURRENT:-22}"
  local ok="false"

  case "$backend" in
    ufw)
      if have_cmd ufw && ufw status 2>/dev/null | grep -qi "Status: active"; then
        ok="true"
        if ! ufw status 2>/dev/null | grep -q "$sshp"; then
          record_finding "Firewall SSH" "FAIL" "CRITICAL" \
            "UFW is active but SSH port is not listed" "missing ${sshp}" "allow ${sshp}/tcp" \
            "ufw allow ${sshp}/tcp" "CIS 3.5.1"
        fi
      fi
      ;;
    firewalld)
      if have_cmd firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
        ok="true"
      fi
      ;;
    nftables)
      if have_cmd nft && nft list ruleset 2>/dev/null | grep -q table; then
        ok="true"
      fi
      ;;
  esac

  if [[ "$ok" == "true" ]]; then
    record_finding "Firewall" "PASS" "INFO" "A host firewall is active" "$backend" "active firewall" \
      "No action" "CIS 3.5 / CIS Control 12"
  else
    record_finding "Firewall" "WARN" "HIGH" "No active host firewall detected" "${backend:-unknown}" "active" \
      "Apply the firewall module without locking out SSH" "CIS 3.5"
  fi
}

#!/usr/bin/env bash
# Firewall hardening with SSH lockout protection.

_fw_backend() {
  printf '%s' "${FIREWALL_BACKEND:-$FIREWALL_BACKEND_DETECTED}"
}

_fw_ssh_port() {
  if [[ -n "${SSH_PORT:-}" ]]; then
    printf '%s' "$SSH_PORT"
  else
    printf '%s' "${SSH_PORT_CURRENT:-22}"
  fi
}

_fw_extra_ports() {
  split_list "${FIREWALL_ALLOWED_PORTS:-}"
}

module_firewall_audit() {
  local backend
  backend="$(_fw_backend)"
  local sshp
  sshp="$(_fw_ssh_port)"

  record_finding "Firewall Backend" "INFO" "INFO" \
    "Detected firewall framework" "$backend" "ufw, firewalld, or nftables" \
    "Install/enable the backend appropriate for this OS" "CIS 3.5 / CIS Control 12"

  case "$backend" in
    ufw)
      if have_cmd ufw && ufw status 2>/dev/null | grep -qi "Status: active"; then
        record_finding "Firewall" "PASS" "INFO" "UFW is active" "active" "active" "No action" "CIS 3.5.1"
      else
        record_finding "Firewall" "WARN" "HIGH" "UFW is not active" "inactive" "active" \
          "Apply the firewall module after confirming SSH port ${sshp}" "CIS 3.5.1"
      fi
      ;;
    firewalld)
      if have_cmd firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
        record_finding "Firewall" "PASS" "INFO" "firewalld is running" "running" "running" "No action" "CIS 3.5.2"
      else
        record_finding "Firewall" "WARN" "HIGH" "firewalld is not running" "stopped" "running" \
          "Apply the firewall module after confirming SSH port ${sshp}" "CIS 3.5.2"
      fi
      ;;
    nftables)
      if have_cmd nft && nft list ruleset 2>/dev/null | grep -q table; then
        record_finding "Firewall" "PASS" "INFO" "nftables ruleset present" "present" "present" "No action" "CIS 3.5.3"
      else
        record_finding "Firewall" "WARN" "MEDIUM" "No nftables tables detected" "empty" "managed ruleset" \
          "Apply the firewall module" "CIS 3.5.3"
      fi
      ;;
  esac

  if have_cmd ss; then
    local listeners
    listeners="$(ss -lntH 2>/dev/null | awk '{print $4}' | tr '\n' ',' | sed 's/,$//')"
    record_finding "Listening Ports" "INFO" "INFO" \
      "Current TCP listeners" "${listeners:-none}" "Only required services" \
      "Close unused listeners before tightening the firewall" "CIS Control 12"
  fi
}

module_firewall_plan() {
  local backend sshp
  backend="$(_fw_backend)"
  sshp="$(_fw_ssh_port)"
  printf '  Backend: %s\n' "$backend"
  printf '  Always allow SSH port %s (current session protected)\n' "$sshp"
  printf '  Default deny inbound: %s\n' "${FIREWALL_DEFAULT_DENY:-true}"
  printf '  Extra ports: %s\n' "${FIREWALL_ALLOWED_PORTS:-none}"
  printf '  Extra services: %s\n' "${FIREWALL_ALLOWED_SERVICES:-none}"
  printf '  Show proposed rules and require confirmation before apply\n'
}

_fw_show_proposal() {
  local sshp
  sshp="$(_fw_ssh_port)"
  printf '\n'
  ui_box_top
  ui_box_center "FIREWALL POLICY  ·  $(_fw_backend)"
  ui_box_sep
  ui_box_row "  allow inbound TCP ${sshp} (SSH)"
  if [[ "$sshp" != "$SSH_PORT_CURRENT" ]]; then
    ui_box_row "  allow inbound TCP ${SSH_PORT_CURRENT} (current SSH session port)"
  fi
  local p
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    ui_box_row "  allow inbound TCP ${p}"
  done < <(_fw_extra_ports)
  if [[ -n "${FIREWALL_ALLOWED_SERVICES:-}" ]]; then
    ui_box_row "  allow services: ${FIREWALL_ALLOWED_SERVICES}"
  fi
  if is_true "${FIREWALL_DEFAULT_DENY:-true}"; then
    ui_box_row "  default deny inbound"
  fi
  if is_true "${FIREWALL_ALLOW_OUTBOUND:-true}"; then
    ui_box_row "  allow outbound"
  fi
  ui_box_bottom
  printf '\n'
}

_fw_apply_ufw() {
  install_package ufw || true
  have_cmd ufw || { log_error "ufw is not available"; return 1; }
  backup_paths firewall /etc/ufw /etc/default/ufw

  local sshp
  sshp="$(_fw_ssh_port)"
  log_action "UFW allow ${sshp}/tcp"
  if [[ "$sshp" != "$SSH_PORT_CURRENT" ]]; then
    log_action "UFW allow ${SSH_PORT_CURRENT}/tcp (existing session)"
  fi
  local p
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    log_action "UFW allow ${p}/tcp"
  done < <(_fw_extra_ports)
  if is_true "${FIREWALL_DEFAULT_DENY:-true}"; then
    log_action "UFW default deny incoming"
  fi
  log_action "UFW default allow outgoing"
  log_action "UFW enable"

  changes_allowed || return 0
  ufw --force reset >/dev/null 2>&1 || true
  ufw default deny incoming
  if is_true "${FIREWALL_ALLOW_OUTBOUND:-true}"; then
    ufw default allow outgoing
  fi
  ufw allow "${sshp}/tcp" comment "SSH-hardener"
  if [[ "$sshp" != "$SSH_PORT_CURRENT" ]]; then
    ufw allow "${SSH_PORT_CURRENT}/tcp" comment "SSH-current-session"
  fi
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    ufw allow "${p}/tcp" comment "hardener-allowed"
  done < <(_fw_extra_ports)
  ufw --force enable
}

_fw_apply_firewalld() {
  if ! have_cmd firewall-cmd; then
    install_package firewalld || true
  fi
  have_cmd firewall-cmd || { log_error "firewalld is not available"; return 1; }
  backup_paths firewall /etc/firewalld

  local sshp
  sshp="$(_fw_ssh_port)"
  log_action "firewalld allow port ${sshp}/tcp"
  changes_allowed || return 0

  svc_enable firewalld
  svc_start firewalld
  firewall-cmd --permanent --add-service=ssh 2>/dev/null || true
  firewall-cmd --permanent --add-port="${sshp}/tcp"
  if [[ "$sshp" != "$SSH_PORT_CURRENT" ]]; then
    firewall-cmd --permanent --add-port="${SSH_PORT_CURRENT}/tcp"
  fi
  local p
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    firewall-cmd --permanent --add-port="${p}/tcp"
  done < <(_fw_extra_ports)
  local svc
  while IFS= read -r svc; do
    [[ -z "$svc" ]] && continue
    firewall-cmd --permanent --add-service="$svc"
  done < <(split_list "${FIREWALL_ALLOWED_SERVICES:-}")
  firewall-cmd --reload
}

_fw_apply_nftables() {
  if ! have_cmd nft; then
    install_package nftables || true
  fi
  have_cmd nft || { log_error "nft is not available"; return 1; }
  backup_paths firewall /etc/nftables.conf

  local sshp file
  sshp="$(_fw_ssh_port)"
  file="/etc/nftables.d/99-server-hardening.nft"
  mkdir -p /etc/nftables.d 2>/dev/null || true

  local extra=""
  local p
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    extra+="    tcp dport ${p} accept"$'\n'
  done < <(_fw_extra_ports)
  if [[ "$sshp" != "$SSH_PORT_CURRENT" ]]; then
    extra+="    tcp dport ${SSH_PORT_CURRENT} accept"$'\n'
  fi

  local content
  content="$(cat <<EOF
#!/usr/sbin/nft -f
table inet server_hardener {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    tcp dport ${sshp} accept
${extra}    icmp type echo-request accept
    ip6 nexthdr icmpv6 accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
  chain output {
    type filter hook output priority 0; policy accept;
  }
}
EOF
)"
  log_action "Write nftables rules ${file}"
  if changes_allowed; then
    write_managed_file "$file" 0640 firewall <<<"$content"
    nft -f "$file"
    if [[ -f /etc/nftables.conf ]] && ! grep -q '99-server-hardening.nft' /etc/nftables.conf; then
      upsert_marked_block /etc/nftables.conf "nftables-include" firewall "include \"${file}\""
    fi
    svc_enable nftables 2>/dev/null || true
  fi
}

module_firewall_apply() {
  announce_defense FIREWALL_DEFAULT_DENY "Firewall default-deny inbound"
  current_ssh_port_protected "$(_fw_ssh_port)" || true
  _fw_show_proposal

  if ! is_true "$NON_INTERACTIVE"; then
    if ! prompt_yes_no "Apply these firewall rules? SSH port $(_fw_ssh_port) will remain allowed" "n"; then
      log_warning "Firewall changes cancelled"
      return 0
    fi
  fi

  case "$(_fw_backend)" in
    ufw) _fw_apply_ufw ;;
    firewalld) _fw_apply_firewalld ;;
    nftables) _fw_apply_nftables ;;
    *) log_error "Unknown firewall backend: $(_fw_backend)"; return 1 ;;
  esac
}

module_firewall_validate() {
  local sshp
  sshp="$(_fw_ssh_port)"
  case "$(_fw_backend)" in
    ufw)
      have_cmd ufw || return 0
      if ! ufw status 2>/dev/null | grep -q "$sshp"; then
        log_error "UFW does not list SSH port ${sshp}"
        return 1
      fi
      ;;
    firewalld)
      have_cmd firewall-cmd || return 0
      firewall-cmd --query-port="${sshp}/tcp" >/dev/null 2>&1 || \
        log_warning "firewalld query for ${sshp}/tcp did not succeed"
      ;;
    nftables)
      have_cmd nft || return 0
      nft list ruleset 2>/dev/null | grep -q "$sshp" || \
        log_warning "nftables ruleset may not include port ${sshp}"
      ;;
  esac
  return 0
}

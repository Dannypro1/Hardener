#!/usr/bin/env bash
# Firewall hardening. Administrator chooses ports and IPs; SSH is never locked out.

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

_fw_open_ports() {
  split_list "${FIREWALL_OPEN_PORTS:-}"
}

_fw_inbound_sources() {
  split_list "${FIREWALL_INBOUND_SOURCES:-}"
}

# Restricted (sourced) vs discovery (any). Empty lists are filled from the role.
_fw_apply_role() {
  case "${FIREWALL_ROLE:-generic}" in
    unifi)
      FIREWALL_ALLOWED_PORTS="${FIREWALL_ALLOWED_PORTS:-8443/tcp,443/tcp,8843/tcp,8880/tcp}"
      FIREWALL_OPEN_PORTS="${FIREWALL_OPEN_PORTS:-3478/udp,10001/udp,1900/udp,8080/tcp,6789/tcp}"
      ;;
    rpki)
      FIREWALL_ALLOWED_PORTS="${FIREWALL_ALLOWED_PORTS:-443/tcp,8323/tcp,3323/tcp}"
      FIREWALL_OPEN_PORTS="${FIREWALL_OPEN_PORTS:-}"
      ;;
    generic|*)
      ;;
  esac
}

_fw_outbound_ports() {
  split_list "${FIREWALL_OUTBOUND_PORTS:-}"
}

_fw_outbound_dests() {
  split_list "${FIREWALL_OUTBOUND_DESTS:-}"
}

_fw_port_num() {
  printf '%s' "${1%%/*}"
}

_fw_port_proto() {
  local spec="$1"
  if [[ "$spec" == */* ]]; then
    printf '%s' "${spec##*/}"
  else
    printf 'tcp'
  fi
}

_fw_valid_port() {
  local spec="$1"
  local port proto
  if [[ ! "$spec" =~ ^[0-9]+(/(tcp|udp))?$ ]]; then
    return 1
  fi
  port="$(_fw_port_num "$spec")"
  proto="$(_fw_port_proto "$spec")"
  [[ "$port" -ge 1 && "$port" -le 65535 ]] || return 1
  [[ "$proto" == "tcp" || "$proto" == "udp" ]]
}

_fw_valid_addr() {
  local a="$1"
  [[ "$a" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$ ]] && return 0
  # IPv6 must contain a colon so words like "bad" are not accepted.
  [[ "$a" == *:* && "$a" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]] && return 0
  return 1
}

_fw_normalize_list() {
  local raw="$1"
  local kind="$2"
  local out=()
  local item
  while IFS= read -r item; do
    item="$(trim "$item")"
    [[ -z "$item" ]] && continue
    if [[ "$kind" == "port" ]]; then
      _fw_valid_port "$item" || continue
    else
      _fw_valid_addr "$item" || continue
    fi
    out+=("$item")
  done < <(split_list "$raw")
  (IFS=','; printf '%s' "${out[*]}")
}

_fw_client_ip() {
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    printf '%s' "${SSH_CONNECTION%% *}"
    return 0
  fi
  if [[ -n "${SSH_CLIENT:-}" ]]; then
    printf '%s' "${SSH_CLIENT%% *}"
    return 0
  fi
  printf ''
}

_fw_protect_ssh_source() {
  local client
  client="$(_fw_client_ip)"
  [[ -z "$client" ]] && return 0
  [[ -z "${FIREWALL_INBOUND_SOURCES:-}" ]] && return 0
  if printf '%s\n' ${FIREWALL_INBOUND_SOURCES//,/ } | grep -qx "$client"; then
    return 0
  fi
  FIREWALL_INBOUND_SOURCES="${client},${FIREWALL_INBOUND_SOURCES}"
  log_warning "Added current SSH client ${client} to inbound sources to avoid lockout"
}

_fw_outbound_restricted() {
  [[ -n "${FIREWALL_OUTBOUND_PORTS:-}" || -n "${FIREWALL_OUTBOUND_DESTS:-}" ]] || \
    is_false "${FIREWALL_ALLOW_OUTBOUND:-true}"
}

_fw_show_listeners() {
  if ! have_cmd ss; then
    return 0
  fi
  ui_box_row "  Listening now:"
  local line port
  while IFS= read -r line; do
    port="$(printf '%s' "$line" | awk '{print $4}' | awk -F: '{print $NF}')"
    [[ -z "$port" ]] && continue
    ui_box_row "    ${port}"
  done < <(ss -lntH 2>/dev/null | head -n 12)
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
}

module_firewall_plan() {
  _fw_apply_role
  printf '  Backend: %s\n' "$(_fw_backend)"
  printf '  Role: %s\n' "${FIREWALL_ROLE:-generic}"
  printf '  SSH port always allowed: %s\n' "$(_fw_ssh_port)"
  printf '  Restricted ports (sourced): %s\n' "${FIREWALL_ALLOWED_PORTS:-SSH only}"
  printf '  Discovery ports (any source): %s\n' "${FIREWALL_OPEN_PORTS:-none}"
  printf '  Inbound sources for SSH/UI: %s\n' "${FIREWALL_INBOUND_SOURCES:-any}"
  if _fw_outbound_restricted; then
    printf '  Outbound: restricted  ports=%s  dests=%s\n' \
      "${FIREWALL_OUTBOUND_PORTS:-any-port}" "${FIREWALL_OUTBOUND_DESTS:-any-dest}"
  else
    printf '  Outbound: allow all\n'
  fi
  printf '  Interactive apply asks for ports and IPs unless --non-interactive\n'
}

_fw_show_proposal() {
  local sshp
  sshp="$(_fw_ssh_port)"
  printf '\n'
  ui_box_top
  ui_box_center "FIREWALL POLICY  ·  $(_fw_backend)"
  ui_box_sep
  ui_box_row "  INBOUND"
  ui_box_row "    SSH TCP ${sshp}  (always)"
  if [[ "$sshp" != "$SSH_PORT_CURRENT" ]]; then
    ui_box_row "    SSH session TCP ${SSH_PORT_CURRENT}"
  fi
  local p
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    ui_box_row "    UI/admin $(_fw_port_proto "$p")/$(_fw_port_num "$p")  (sourced)"
  done < <(_fw_extra_ports)
  if [[ -n "${FIREWALL_INBOUND_SOURCES:-}" ]]; then
    ui_box_row "    SSH/UI from ${FIREWALL_INBOUND_SOURCES}"
  else
    ui_box_row "    SSH/UI from any address"
  fi
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    ui_box_row "    discovery $(_fw_port_proto "$p")/$(_fw_port_num "$p")  (any source)"
  done < <(_fw_open_ports)
  ui_box_sep
  ui_box_row "  OUTBOUND"
  if _fw_outbound_restricted; then
    ui_box_row "    default deny (established replies still allowed)"
    if [[ -n "${FIREWALL_OUTBOUND_PORTS:-}" ]]; then
      ui_box_row "    ports ${FIREWALL_OUTBOUND_PORTS}"
    fi
    if [[ -n "${FIREWALL_OUTBOUND_DESTS:-}" ]]; then
      ui_box_row "    destinations ${FIREWALL_OUTBOUND_DESTS}"
    fi
  else
    ui_box_row "    allow all"
  fi
  ui_box_bottom
  printf '\n'
}

_fw_collect_policy() {
  _fw_apply_role
  if is_true "$NON_INTERACTIVE"; then
    FIREWALL_ALLOWED_PORTS="$(_fw_normalize_list "${FIREWALL_ALLOWED_PORTS:-}" port)"
    FIREWALL_OPEN_PORTS="$(_fw_normalize_list "${FIREWALL_OPEN_PORTS:-}" port)"
    FIREWALL_INBOUND_SOURCES="$(_fw_normalize_list "${FIREWALL_INBOUND_SOURCES:-}" addr)"
    FIREWALL_OUTBOUND_PORTS="$(_fw_normalize_list "${FIREWALL_OUTBOUND_PORTS:-}" port)"
    FIREWALL_OUTBOUND_DESTS="$(_fw_normalize_list "${FIREWALL_OUTBOUND_DESTS:-}" addr)"
    _fw_protect_ssh_source
    return 0
  fi

  printf '\n'
  ui_box_top
  ui_box_center "CHOOSE FIREWALL ACCESS"
  ui_box_sep
  ui_box_row "  SSH port $(_fw_ssh_port) stays allowed."
  ui_box_row "  UI/admin ports are sourced. Discovery ports stay open."
  _fw_show_listeners
  ui_box_sep
  ui_box_row "  [1]  SSH only"
  ui_box_row "  [2]  Web  (80, 443)"
  ui_box_row "  [3]  Web + custom ports"
  ui_box_row "  [4]  Custom ports and IPs"
  ui_box_row "  [5]  UniFi OS  (web sourced, AP discovery open)"
  ui_box_row "  [6]  RPKI  (relevant ports sourced only)"
  ui_box_bottom
  printf '\n'
  local preset
  preset="$(prompt_choice "Choice" 1 6 4)"
  case "$preset" in
    1)
      FIREWALL_ROLE="generic"
      FIREWALL_ALLOWED_PORTS=""
      FIREWALL_OPEN_PORTS=""
      ;;
    2)
      FIREWALL_ROLE="generic"
      FIREWALL_ALLOWED_PORTS="80,443"
      FIREWALL_OPEN_PORTS=""
      ;;
    3)
      FIREWALL_ROLE="generic"
      FIREWALL_ALLOWED_PORTS="80,443"
      ;;
    5)
      FIREWALL_ROLE="unifi"
      FIREWALL_ALLOWED_PORTS="8443/tcp,443/tcp,8843/tcp,8880/tcp"
      FIREWALL_OPEN_PORTS="3478/udp,10001/udp,1900/udp,8080/tcp,6789/tcp"
      ;;
    6)
      FIREWALL_ROLE="rpki"
      FIREWALL_ALLOWED_PORTS="443/tcp,8323/tcp,3323/tcp"
      FIREWALL_OPEN_PORTS=""
      ;;
  esac

  if [[ "$preset" == "3" || "$preset" == "4" ]]; then
    local ports
    ports="$(prompt_read "Restricted inbound ports (sourced, e.g. 80,443,8443/tcp)" "${FIREWALL_ALLOWED_PORTS}")"
    FIREWALL_ALLOWED_PORTS="$(_fw_normalize_list "$ports" port)"
    ports="$(prompt_read "Discovery ports from any source (empty = none)" "${FIREWALL_OPEN_PORTS}")"
    FIREWALL_OPEN_PORTS="$(_fw_normalize_list "$ports" port)"
  fi

  local sources
  sources="$(prompt_read "Inbound source IPs/CIDRs for SSH/UI (empty = any)" "${FIREWALL_INBOUND_SOURCES}")"
  FIREWALL_INBOUND_SOURCES="$(_fw_normalize_list "$sources" addr)"

  printf '\n'
  ui_box_top
  ui_box_center "OUTBOUND POLICY"
  ui_box_sep
  ui_box_row "  [1]  Allow all outbound"
  ui_box_row "  [2]  Allow only listed ports"
  ui_box_row "  [3]  Allow only listed destination IPs"
  ui_box_row "  [4]  Allow listed ports to listed IPs"
  ui_box_row "  [5]  Deny all new outbound (replies still work)"
  ui_box_bottom
  printf '\n'
  local outc
  outc="$(prompt_choice "Choice" 1 5 1)"
  FIREWALL_OUTBOUND_PORTS=""
  FIREWALL_OUTBOUND_DESTS=""
  FIREWALL_ALLOW_OUTBOUND=true
  case "$outc" in
    1) FIREWALL_ALLOW_OUTBOUND=true ;;
    2)
      FIREWALL_ALLOW_OUTBOUND=false
      FIREWALL_OUTBOUND_PORTS="$(_fw_normalize_list "$(prompt_read "Outbound ports (e.g. 80,443,53/udp)" "80,443,53/udp")" port)"
      ;;
    3)
      FIREWALL_ALLOW_OUTBOUND=false
      FIREWALL_OUTBOUND_DESTS="$(_fw_normalize_list "$(prompt_read "Outbound destination IPs/CIDRs" "")" addr)"
      ;;
    4)
      FIREWALL_ALLOW_OUTBOUND=false
      FIREWALL_OUTBOUND_PORTS="$(_fw_normalize_list "$(prompt_read "Outbound ports" "80,443,53/udp")" port)"
      FIREWALL_OUTBOUND_DESTS="$(_fw_normalize_list "$(prompt_read "Outbound destination IPs/CIDRs" "")" addr)"
      ;;
    5)
      FIREWALL_ALLOW_OUTBOUND=false
      ;;
  esac

  _fw_protect_ssh_source
}

_fw_emit_inbound() {
  # Prints: proto port [source]   — empty source means any
  local spec="$1"
  local sourced="${2:-true}"
  local proto port src
  proto="$(_fw_port_proto "$spec")"
  port="$(_fw_port_num "$spec")"
  if is_true "$sourced" && [[ -n "${FIREWALL_INBOUND_SOURCES:-}" ]]; then
    while IFS= read -r src; do
      [[ -z "$src" ]] && continue
      printf '%s %s %s\n' "$proto" "$port" "$src"
    done < <(_fw_inbound_sources)
  else
    printf '%s %s\n' "$proto" "$port"
  fi
}

_fw_each_inbound_allow() {
  # Prints: proto port [source]
  local extra
  _fw_emit_inbound "$(_fw_ssh_port)/tcp" true
  if [[ "$(_fw_ssh_port)" != "$SSH_PORT_CURRENT" ]]; then
    _fw_emit_inbound "${SSH_PORT_CURRENT}/tcp" true
  fi
  while IFS= read -r extra; do
    [[ -z "$extra" ]] && continue
    _fw_emit_inbound "$extra" true
  done < <(_fw_extra_ports)
  while IFS= read -r extra; do
    [[ -z "$extra" ]] && continue
    _fw_emit_inbound "$extra" false
  done < <(_fw_open_ports)
}

_fw_apply_ufw() {
  install_package ufw || true
  have_cmd ufw || { log_error "ufw is not available"; return 1; }
  backup_paths firewall /etc/ufw /etc/default/ufw

  local proto port src
  while read -r proto port src; do
    [[ -z "$port" ]] && continue
    if [[ -n "$src" ]]; then
      log_action "UFW allow from ${src} to ${port}/${proto}"
    else
      log_action "UFW allow ${port}/${proto}"
    fi
  done < <(_fw_each_inbound_allow)

  if _fw_outbound_restricted; then
    log_action "UFW default deny outgoing"
  else
    log_action "UFW default allow outgoing"
  fi

  changes_allowed || return 0
  ufw --force reset >/dev/null 2>&1 || true
  ufw default deny incoming
  if _fw_outbound_restricted; then
    ufw default deny outgoing
  else
    ufw default allow outgoing
  fi

  while read -r proto port src; do
    [[ -z "$port" ]] && continue
    if [[ -n "$src" ]]; then
      ufw allow from "$src" to any port "$port" proto "$proto" comment "hardener-in"
    else
      ufw allow "${port}/${proto}" comment "hardener-in"
    fi
  done < <(_fw_each_inbound_allow)

  if _fw_outbound_restricted; then
    local d p
    if [[ -n "${FIREWALL_OUTBOUND_DESTS:-}" && -n "${FIREWALL_OUTBOUND_PORTS:-}" ]]; then
      while IFS= read -r d; do
        [[ -z "$d" ]] && continue
        while IFS= read -r p; do
          [[ -z "$p" ]] && continue
          ufw allow out to "$d" port "$(_fw_port_num "$p")" proto "$(_fw_port_proto "$p")" comment "hardener-out"
        done < <(_fw_outbound_ports)
      done < <(_fw_outbound_dests)
    elif [[ -n "${FIREWALL_OUTBOUND_DESTS:-}" ]]; then
      while IFS= read -r d; do
        [[ -z "$d" ]] && continue
        ufw allow out to "$d" comment "hardener-out"
      done < <(_fw_outbound_dests)
    elif [[ -n "${FIREWALL_OUTBOUND_PORTS:-}" ]]; then
      while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        ufw allow out "$(_fw_port_num "$p")/$(_fw_port_proto "$p")" comment "hardener-out"
      done < <(_fw_outbound_ports)
    fi
  fi
  ufw --force enable
}

_fw_apply_firewalld() {
  if ! have_cmd firewall-cmd; then
    install_package firewalld || true
  fi
  have_cmd firewall-cmd || { log_error "firewalld is not available"; return 1; }
  backup_paths firewall /etc/firewalld

  changes_allowed || return 0
  svc_enable firewalld
  svc_start firewalld

  local proto port src
  while read -r proto port src; do
    [[ -z "$port" ]] && continue
    if [[ -n "$src" ]]; then
      local fam="ipv4"
      [[ "$src" == *:* ]] && fam="ipv6"
      log_action "firewalld allow ${fam} ${src} -> ${port}/${proto}"
      firewall-cmd --permanent --add-rich-rule="rule family=\"${fam}\" source address=\"${src}\" port port=\"${port}\" protocol=\"${proto}\" accept"
    else
      log_action "firewalld allow ${port}/${proto}"
      firewall-cmd --permanent --add-port="${port}/${proto}"
    fi
  done < <(_fw_each_inbound_allow)

  local svc
  while IFS= read -r svc; do
    [[ -z "$svc" ]] && continue
    firewall-cmd --permanent --add-service="$svc"
  done < <(split_list "${FIREWALL_ALLOWED_SERVICES:-}")

  if _fw_outbound_restricted; then
    firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -o lo -j ACCEPT
    local d p
    if [[ -n "${FIREWALL_OUTBOUND_DESTS:-}" && -n "${FIREWALL_OUTBOUND_PORTS:-}" ]]; then
      while IFS= read -r d; do
        [[ -z "$d" ]] && continue
        while IFS= read -r p; do
          [[ -z "$p" ]] && continue
          firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 1 -d "$d" -p "$(_fw_port_proto "$p")" --dport "$(_fw_port_num "$p")" -j ACCEPT
        done < <(_fw_outbound_ports)
      done < <(_fw_outbound_dests)
    elif [[ -n "${FIREWALL_OUTBOUND_DESTS:-}" ]]; then
      while IFS= read -r d; do
        [[ -z "$d" ]] && continue
        firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 1 -d "$d" -j ACCEPT
      done < <(_fw_outbound_dests)
    elif [[ -n "${FIREWALL_OUTBOUND_PORTS:-}" ]]; then
      while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 1 -p "$(_fw_port_proto "$p")" --dport "$(_fw_port_num "$p")" -j ACCEPT
      done < <(_fw_outbound_ports)
    fi
    firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 100 -j DROP
  fi
  firewall-cmd --reload
}

_fw_apply_nftables() {
  if ! have_cmd nft; then
    install_package nftables || true
  fi
  have_cmd nft || { log_error "nft is not available"; return 1; }
  backup_paths firewall /etc/nftables.conf

  local file="/etc/nftables.d/99-server-hardening.nft"
  mkdir -p /etc/nftables.d 2>/dev/null || true

  local in_rules="" proto port src
  while read -r proto port src; do
    [[ -z "$port" ]] && continue
    if [[ -n "$src" ]]; then
      if [[ "$src" == *:* ]]; then
        in_rules+="    ip6 saddr ${src} ${proto} dport ${port} accept"$'\n'
      else
        in_rules+="    ip saddr ${src} ${proto} dport ${port} accept"$'\n'
      fi
    else
      in_rules+="    ${proto} dport ${port} accept"$'\n'
    fi
  done < <(_fw_each_inbound_allow)

  local out_policy="accept"
  local out_rules=""
  if _fw_outbound_restricted; then
    out_policy="drop"
    out_rules+="    ct state established,related accept"$'\n'
    out_rules+="    oif lo accept"$'\n'
    local d p
    if [[ -n "${FIREWALL_OUTBOUND_DESTS:-}" && -n "${FIREWALL_OUTBOUND_PORTS:-}" ]]; then
      while IFS= read -r d; do
        [[ -z "$d" ]] && continue
        while IFS= read -r p; do
          [[ -z "$p" ]] && continue
          if [[ "$d" == *:* ]]; then
            out_rules+="    ip6 daddr ${d} $(_fw_port_proto "$p") dport $(_fw_port_num "$p") accept"$'\n'
          else
            out_rules+="    ip daddr ${d} $(_fw_port_proto "$p") dport $(_fw_port_num "$p") accept"$'\n'
          fi
        done < <(_fw_outbound_ports)
      done < <(_fw_outbound_dests)
    elif [[ -n "${FIREWALL_OUTBOUND_DESTS:-}" ]]; then
      while IFS= read -r d; do
        [[ -z "$d" ]] && continue
        if [[ "$d" == *:* ]]; then
          out_rules+="    ip6 daddr ${d} accept"$'\n'
        else
          out_rules+="    ip daddr ${d} accept"$'\n'
        fi
      done < <(_fw_outbound_dests)
    elif [[ -n "${FIREWALL_OUTBOUND_PORTS:-}" ]]; then
      while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        out_rules+="    $(_fw_port_proto "$p") dport $(_fw_port_num "$p") accept"$'\n'
      done < <(_fw_outbound_ports)
    fi
  else
    out_rules+="    # unrestricted outbound"$'\n'
  fi

  local content
  content="$(cat <<EOF
#!/usr/sbin/nft -f
table inet server_hardener {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
${in_rules}    icmp type echo-request accept
    ip6 nexthdr icmpv6 accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
  chain output {
    type filter hook output priority 0; policy ${out_policy};
${out_rules}  }
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
  _fw_collect_policy
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

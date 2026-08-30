#!/usr/bin/env bash
# Optional Wazuh agent. No credentials or keys are stored in the repo or logs.

WAZUH_SERVICE="wazuh-agent"

_wazuh_installed() {
  have_cmd wazuh-control || is_package_installed wazuh-agent || [[ -x /var/ossec/bin/wazuh-control ]]
}

_wazuh_control() {
  if have_cmd wazuh-control; then
    wazuh-control "$@"
  elif [[ -x /var/ossec/bin/wazuh-control ]]; then
    /var/ossec/bin/wazuh-control "$@"
  else
    return 1
  fi
}

_wazuh_ossec_conf() {
  if [[ -f /var/ossec/etc/ossec.conf ]]; then
    printf '/var/ossec/etc/ossec.conf'
  elif [[ -f /etc/ossec.conf ]]; then
    printf '/etc/ossec.conf'
  else
    printf ''
  fi
}

_wazuh_agent_name() {
  printf '%s' "${WAZUH_AGENT_NAME:-$(hostname -s 2>/dev/null || hostname)}"
}

_wazuh_collect_audit() {
  local conf
  conf="$(_wazuh_ossec_conf)"
  [[ -n "$conf" && -f "$conf" ]] || return 0
  if is_false "${WAZUH_COLLECT_AUDIT:-true}"; then
    return 0
  fi
  if grep -q '<location>/var/log/audit/audit.log</location>' "$conf"; then
    log_info "Wazuh already collects /var/log/audit/audit.log"
    return 0
  fi
  backup_file "$conf" wazuh
  log_action "Add auditd localfile to ossec.conf"
  if ! changes_allowed; then
    return 0
  fi
  local tmp
  tmp="$(mktemp)"
  awk '
    /<\/ossec_config>/ && !done {
      print "  <localfile>"
      print "    <log_format>audit</log_format>"
      print "    <location>/var/log/audit/audit.log</location>"
      print "  </localfile>"
      done=1
    }
    { print }
  ' "$conf" > "$tmp"
  mv "$tmp" "$conf"
  chmod 0640 "$conf"
  chown root:wazuh "$conf" 2>/dev/null || chown root:root "$conf"
}

module_wazuh_audit() {
  if _wazuh_installed; then
    local state="unknown"
    if svc_is_active wazuh-agent; then
      state="active"
    elif _wazuh_control status >/dev/null 2>&1; then
      state="control-ok"
    else
      state="installed-inactive"
    fi
    if [[ "$state" == "active" || "$state" == "control-ok" ]]; then
      record_finding "Wazuh" "PASS" "INFO" "Wazuh agent is present" "$state" "running agent if required" \
        "Confirm manager connectivity from the Wazuh UI" "CIS Control 8 / NIST AU-6"
    else
      record_finding "Wazuh" "WARN" "MEDIUM" "Wazuh agent installed but not running" "$state" "active" \
        "Start wazuh-agent after configuration and registration" "CIS Control 8"
    fi
  elif is_true "${WAZUH_ENABLED:-false}"; then
    record_finding "Wazuh" "FAIL" "MEDIUM" "Wazuh requested but not installed" "missing" "wazuh-agent" \
      "Run the Wazuh module to install and register" "CIS Control 8"
  else
    record_finding "Wazuh" "INFO" "INFO" "Wazuh is optional and not enabled" "disabled" "optional" \
      "No action" "CIS Control 8"
  fi
}

module_wazuh_plan() {
  printf '  Optional Wazuh agent (not assumed local manager)\n'
  printf '  Manager: %s  Agent name: %s\n' "${WAZUH_MANAGER:-ask}" "$(_wazuh_agent_name)"
  printf '  Collect audit.log: %s\n' "${WAZUH_COLLECT_AUDIT:-true}"
  printf '  Registration secrets are never written to logs\n'
}

_wazuh_menu() {
  if is_true "$NON_INTERACTIVE"; then
    if is_true "${WAZUH_ENABLED:-false}"; then
      printf '2'
    else
      printf '6'
    fi
    return 0
  fi
  printf '\n'
  ui_box_top
  ui_box_center "WAZUH INTEGRATION"
  ui_box_sep
  ui_box_row " [1]  Check existing agent"
  ui_box_row " [2]  Install Wazuh Agent"
  ui_box_row " [3]  Configure Agent"
  ui_box_row " [4]  Register Agent"
  ui_box_row " [5]  Validate"
  ui_box_row " [6]  Skip"
  ui_box_bottom
  printf '\n'
  prompt_choice "Choice" 1 6 6
}

_wazuh_check_existing() {
  if _wazuh_installed; then
    log_success "Wazuh agent binaries are present"
    _wazuh_control info 2>/dev/null || true
    svc_status_line wazuh-agent || true
  else
    log_info "No Wazuh agent detected"
  fi
}

_wazuh_install() {
  if _wazuh_installed; then
    log_info "Wazuh agent already installed"
    return 0
  fi
  case "$(os_family)" in
    debian)
      log_action "Add Wazuh apt repository and install wazuh-agent"
      if changes_allowed; then
        if ! have_cmd curl; then
          install_package curl || true
        fi
        # Official signed repo. GPG key is fetched over HTTPS.
        install -d /usr/share/keyrings
        if [[ ! -f /usr/share/keyrings/wazuh.gpg ]]; then
          curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
        fi
        printf 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\n' \
          > /etc/apt/sources.list.d/wazuh.list
        export WAZUH_MANAGER="${WAZUH_MANAGER}"
        export WAZUH_AGENT_NAME="$(_wazuh_agent_name)"
        update_package_index
        install_package wazuh-agent
      fi
      ;;
    rhel)
      log_action "Add Wazuh yum/dnf repository and install wazuh-agent"
      if changes_allowed; then
        export WAZUH_MANAGER="${WAZUH_MANAGER}"
        export WAZUH_AGENT_NAME="$(_wazuh_agent_name)"
        cat > /etc/yum.repos.d/wazuh.repo <<'EOF'
[wazuh]
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
protect=1
EOF
        update_package_index
        install_package wazuh-agent
      fi
      ;;
    *)
      log_error "Unsupported family for automated Wazuh install"
      return 1
      ;;
  esac
}

_wazuh_configure() {
  local conf
  conf="$(_wazuh_ossec_conf)"
  if [[ -z "$conf" ]]; then
    log_error "ossec.conf not found; install the agent first"
    return 1
  fi
  WAZUH_MANAGER="$(prompt_read "Wazuh manager address" "${WAZUH_MANAGER}")"
  WAZUH_AGENT_NAME="$(prompt_read "Agent name" "$(_wazuh_agent_name)")"
  WAZUH_PORT="$(prompt_read "Manager port" "${WAZUH_PORT:-1514}")"
  if [[ -z "$WAZUH_MANAGER" ]]; then
    log_error "Manager address is required"
    return 1
  fi
  backup_file "$conf" wazuh
  log_action "Set Wazuh manager ${WAZUH_MANAGER} in ossec.conf"
  if changes_allowed; then
    if grep -q '<address>' "$conf"; then
      sed -i -E "0,/<address>.*<\\/address>/s#<address>.*</address>#<address>${WAZUH_MANAGER}</address>#" "$conf"
    fi
    if grep -q '<port>' "$conf"; then
      sed -i -E "0,/<port>.*<\\/port>/s#<port>.*</port>#<port>${WAZUH_PORT}</port>#" "$conf"
    fi
    chmod 0640 "$conf"
    chown root:wazuh "$conf" 2>/dev/null || chown root:root "$conf"
  fi
  _wazuh_collect_audit
}

_wazuh_register() {
  if ! _wazuh_installed; then
    log_error "Install the agent before registration"
    return 1
  fi
  local manager
  manager="$(prompt_read "Registration / manager address" "${WAZUH_REGISTRATION_SERVER:-$WAZUH_MANAGER}")"
  local name
  name="$(prompt_read "Agent name" "$(_wazuh_agent_name)")"
  if [[ -z "$manager" ]]; then
    log_error "Registration server is required"
    return 1
  fi
  log_action "Register Wazuh agent with manager (password not logged)"
  if ! changes_allowed; then
    return 0
  fi
  local pass="${WAZUH_REGISTRATION_PASSWORD:-}"
  if [[ -z "$pass" ]] && ! is_true "$NON_INTERACTIVE"; then
    printf 'Registration password (empty to skip password auth): ' >&2
    IFS= read -rs pass || true
    printf '\n' >&2
  fi
  local args=( -m "$manager" -A "$name" )
  if [[ -n "${WAZUH_AGENT_GROUP:-}" ]]; then
    args+=( -G "$WAZUH_AGENT_GROUP" )
  fi
  if [[ -n "$pass" ]]; then
    args+=( -P "$pass" )
  fi
  if [[ -x /var/ossec/bin/agent-auth ]]; then
    /var/ossec/bin/agent-auth "${args[@]}"
  elif have_cmd agent-auth; then
    agent-auth "${args[@]}"
  else
    log_error "agent-auth not found"
    return 1
  fi
  unset pass
  svc_enable wazuh-agent || true
  svc_restart wazuh-agent || _wazuh_control restart || true
}

_wazuh_validate_now() {
  if ! _wazuh_installed; then
    log_error "Wazuh agent is not installed"
    return 1
  fi
  local conf
  conf="$(_wazuh_ossec_conf)"
  if [[ -z "$conf" ]]; then
    log_error "ossec.conf missing"
    return 1
  fi
  local mode
  mode="$(file_mode "$conf")"
  if [[ "$mode" == "777" || "$mode" == "666" ]]; then
    log_error "ossec.conf permissions are unsafe"
    return 1
  fi
  if svc_is_active wazuh-agent || _wazuh_control status >/dev/null 2>&1; then
    log_success "Wazuh agent service appears healthy"
    return 0
  fi
  log_warning "Wazuh agent is installed but the service is not active"
  return 1
}

module_wazuh_apply() {
  local choice
  choice="$(_wazuh_menu)"
  case "$choice" in
    1) _wazuh_check_existing ;;
    2)
      _wazuh_install
      if [[ -n "${WAZUH_MANAGER:-}" ]]; then
        _wazuh_configure
      fi
      _wazuh_collect_audit
      if changes_allowed; then
        have_cmd systemctl && systemctl daemon-reload || true
        svc_enable wazuh-agent || true
        svc_start wazuh-agent || svc_restart wazuh-agent || true
      fi
      ;;
    3) _wazuh_configure ;;
    4) _wazuh_register ;;
    5) _wazuh_validate_now ;;
    6) log_info "Wazuh skipped" ;;
  esac
  if is_true "$NON_INTERACTIVE" && is_true "${WAZUH_ENABLED:-false}"; then
    _wazuh_install
    _wazuh_configure
    _wazuh_collect_audit
    if [[ -n "${WAZUH_REGISTRATION_PASSWORD:-}" ]]; then
      _wazuh_register
    else
      log_warning "Non-interactive Wazuh install without WAZUH_REGISTRATION_PASSWORD — register later"
    fi
    if changes_allowed; then
      have_cmd systemctl && systemctl daemon-reload || true
    fi
    svc_enable wazuh-agent || true
    svc_start wazuh-agent || svc_restart wazuh-agent || true
    log_info "Check /var/ossec/logs/ossec.log for a successful manager connection"
  fi
}

module_wazuh_validate() {
  if is_true "${WAZUH_ENABLED:-false}" || _wazuh_installed; then
    _wazuh_validate_now || true
  fi
}

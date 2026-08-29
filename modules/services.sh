#!/usr/bin/env bash
# Service hardening. Known-insecure units are disabled; unknowns are left alone.

_svc_list_running() {
  if [[ "$INIT_SYSTEM" == "systemd" ]] && have_cmd systemctl; then
    systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null \
      | awk '{print $1}' | sed 's/\.service$//'
  fi
}

_svc_list_enabled() {
  if [[ "$INIT_SYSTEM" == "systemd" ]] && have_cmd systemctl; then
    systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager 2>/dev/null \
      | awk '{print $1}' | sed 's/\.service$//'
  fi
}

# Clear-text / NIS / TFTP — disabled without a prompt when present.
DANGEROUS_SERVICES="${DANGEROUS_SERVICES:-telnet telnet.socket rsh rsh.socket rlogin rlogin.socket rexec rexec.socket ypbind ypserv tftp tftp.socket tftpd talk.socket ntalk}"

# Often unnecessary on a headless server — confirmation required.
REVIEW_SERVICES="${REVIEW_SERVICES:-avahi-daemon cups bluetooth rpcbind nfs-server}"

_svc_present() {
  local name="$1"
  svc_exists "$name" || svc_is_active "$name" || svc_is_enabled "$name"
}

_svc_disable_safe() {
  local name="$1"
  if is_essential_service "$name"; then
    log_warning "Refusing to disable essential service ${name}"
    return 0
  fi
  if ! _svc_present "$name"; then
    return 0
  fi
  log_action "Disable insecure service ${name}"
  svc_stop "$name" || true
  svc_disable "$name" || true
  if have_cmd systemctl && changes_allowed; then
    systemctl mask "${name}.service" 2>/dev/null || true
    systemctl mask "${name}" 2>/dev/null || true
  fi
}

module_services_audit() {
  local enabled
  enabled="$(_svc_list_enabled | wc -l | tr -d ' ')"
  record_finding "Services" "INFO" "INFO" \
    "Running and enabled services inventoried" \
    "enabled_count=${enabled}" \
    "Only required services enabled" \
    "Dangerous legacy services are disabled automatically" \
    "CIS 2.1 / CIS Control 4"

  local svc
  for svc in $DANGEROUS_SERVICES; do
    if _svc_present "$svc"; then
      record_finding "Service ${svc}" "FAIL" "HIGH" \
        "Insecure legacy service is present" \
        "$(svc_status_line "$svc")" \
        "disabled and masked" \
        "This module disables ${svc} during apply" \
        "CIS 2.2"
    fi
  done
  for svc in $REVIEW_SERVICES; do
    if _svc_present "$svc" && (svc_is_enabled "$svc" || svc_is_active "$svc"); then
      record_finding "Service ${svc}" "WARN" "LOW" \
        "Often-unnecessary service is enabled or running" \
        "$(svc_status_line "$svc")" \
        "disabled unless required" \
        "Confirm before disable" \
        "CIS 2.2"
    fi
  done
}

module_services_plan() {
  printf '  Auto-disable insecure services: %s\n' "$DANGEROUS_SERVICES"
  printf '  Ask before disabling: %s\n' "$REVIEW_SERVICES"
  printf '  Essential services are never disabled: %s\n' "${ESSENTIAL_SERVICES}"
}

module_services_apply() {
  announce_defense SERVICES_AUTO_DISABLE_DANGEROUS "Disable telnet/rsh/NIS/TFTP"
  local svc
  if is_true "${SERVICES_AUTO_DISABLE_DANGEROUS:-true}"; then
    for svc in $DANGEROUS_SERVICES; do
      _svc_disable_safe "$svc"
    done
  fi

  for svc in $REVIEW_SERVICES; do
    if is_essential_service "$svc"; then
      continue
    fi
    if _svc_present "$svc" && (svc_is_enabled "$svc" || svc_is_active "$svc"); then
      if prompt_yes_no "Disable and stop ${svc}?" "n"; then
        _svc_disable_safe "$svc"
      else
        log_info "Left service unchanged: ${svc}"
      fi
    fi
  done
}

module_services_validate() {
  local svc
  for svc in $DANGEROUS_SERVICES; do
    if svc_is_active "$svc" 2>/dev/null; then
      log_warning "Dangerous service still active: ${svc}"
    fi
  done
  return 0
}

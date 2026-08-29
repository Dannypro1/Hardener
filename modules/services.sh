#!/usr/bin/env bash
# Service hardening. Never disables unknown services automatically.

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

# Services commonly unnecessary on a headless server. Recommendations only.
UNNECESSARY_SERVICES="${UNNECESSARY_SERVICES:-avahi-daemon cups bluetooth rpcbind nfs-server ypbind telnet.socket rsh.socket rlogin.socket}"

module_services_audit() {
  local running enabled
  running="$(_svc_list_running | tr '\n' ',' | sed 's/,$//')"
  enabled="$(_svc_list_enabled | wc -l | tr -d ' ')"
  record_finding "Services" "INFO" "INFO" \
    "Running and enabled services inventoried" \
    "enabled_count=${enabled}" \
    "Only required services enabled" \
    "Review recommendations; unknown units are never auto-disabled" \
    "CIS 2.1 / CIS Control 4"

  local svc
  for svc in $UNNECESSARY_SERVICES; do
    if svc_exists "$svc" && (svc_is_enabled "$svc" || svc_is_active "$svc"); then
      record_finding "Service ${svc}" "WARN" "LOW" \
        "Often-unnecessary service is enabled or running" \
        "$(svc_status_line "$svc")" \
        "disabled unless required" \
        "Confirm with the administrator before disabling ${svc}" \
        "CIS 2.2"
    fi
  done
}

module_services_plan() {
  printf '  Inventory running/enabled/listening services\n'
  printf '  Recommend disabling: %s\n' "$UNNECESSARY_SERVICES"
  printf '  Essential services are never auto-disabled: %s\n' "${ESSENTIAL_SERVICES}"
  printf '  Unknown services are never disabled without confirmation\n'
}

module_services_apply() {
  local svc
  for svc in $UNNECESSARY_SERVICES; do
    if is_essential_service "$svc"; then
      continue
    fi
    if svc_exists "$svc" && (svc_is_enabled "$svc" || svc_is_active "$svc"); then
      if prompt_yes_no "Disable and stop ${svc}?" "n"; then
        svc_stop "$svc" || true
        svc_disable "$svc" || true
      else
        log_info "Left service unchanged: ${svc}"
      fi
    fi
  done
}

module_services_validate() {
  return 0
}

#!/usr/bin/env bash
# Time synchronization: chrony, systemd-timesyncd, or ntpd.

_time_detect() {
  if svc_exists chronyd || have_cmd chronyd; then
    printf 'chrony'
  elif svc_exists chrony || have_cmd chrony; then
    printf 'chrony'
  elif svc_exists systemd-timesyncd; then
    printf 'timesyncd'
  elif svc_exists ntpd || have_cmd ntpd; then
    printf 'ntpd'
  else
    printf 'none'
  fi
}

_time_unit() {
  case "$(_time_detect)" in
    chrony)
      if svc_exists chronyd; then printf 'chronyd'; else printf 'chrony'; fi
      ;;
    timesyncd) printf 'systemd-timesyncd' ;;
    ntpd) printf 'ntpd' ;;
    *) printf '' ;;
  esac
}

module_time_sync_audit() {
  local kind unit
  kind="$(_time_detect)"
  unit="$(_time_unit)"
  if [[ "$kind" == "none" ]]; then
    record_finding "Time Sync" "WARN" "MEDIUM" \
      "No NTP client detected" "none" "chrony, timesyncd, or ntpd" \
      "Install chrony (preferred) or enable systemd-timesyncd" \
      "CIS 1.3 / NIST AU-8"
    return 0
  fi
  if [[ -n "$unit" ]] && svc_is_active "$unit"; then
    record_finding "Time Sync" "PASS" "INFO" \
      "Time synchronization is active" "${kind} ${unit}" "enabled NTP client" \
      "No action" "CIS 1.3"
  else
    record_finding "Time Sync" "WARN" "MEDIUM" \
      "Time daemon is installed but not running" "${kind}" "active" \
      "Enable and start ${unit}" "CIS 1.3"
  fi
}

module_time_sync_plan() {
  printf '  Detected time source: %s\n' "$(_time_detect)"
  printf '  Enable the existing client; install chrony only if none exists\n'
}

module_time_sync_apply() {
  local kind unit
  kind="$(_time_detect)"
  if [[ "$kind" == "none" ]]; then
    case "$(os_family)" in
      debian)
        if is_package_installed systemd-timesyncd || svc_exists systemd-timesyncd; then
          kind="timesyncd"
        else
          install_package chrony || install_package systemd-timesyncd || true
          kind="$(_time_detect)"
        fi
        ;;
      rhel)
        install_package chrony || true
        kind="$(_time_detect)"
        ;;
    esac
  fi
  unit="$(_time_unit)"
  if [[ -n "$unit" ]]; then
    svc_enable "$unit"
    svc_start "$unit" || svc_restart "$unit" || true
  else
    log_warning "No time-sync service could be enabled"
  fi
}

module_time_sync_validate() {
  local unit
  unit="$(_time_unit)"
  [[ -z "$unit" ]] && return 0
  svc_is_active "$unit" || log_warning "Time service ${unit} is not active"
}

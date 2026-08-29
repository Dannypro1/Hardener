#!/usr/bin/env bash
# Init-system abstraction. Prefer systemd; fall back to service(8).

svc_exists() {
  local name="$1"
  if [[ "$INIT_SYSTEM" == "systemd" ]] && have_cmd systemctl; then
    systemctl list-unit-files "${name}.service" >/dev/null 2>&1 && \
      systemctl cat "${name}.service" >/dev/null 2>&1
    return
  fi
  [[ -x "/etc/init.d/${name}" ]]
}

svc_is_active() {
  local name="$1"
  if [[ "$INIT_SYSTEM" == "systemd" ]] && have_cmd systemctl; then
    systemctl is-active --quiet "${name}.service"
    return
  fi
  if have_cmd service; then
    service "$name" status >/dev/null 2>&1
    return
  fi
  return 1
}

svc_is_enabled() {
  local name="$1"
  if [[ "$INIT_SYSTEM" == "systemd" ]] && have_cmd systemctl; then
    systemctl is-enabled --quiet "${name}.service" 2>/dev/null
    return
  fi
  return 1
}

svc_enable() {
  local name="$1"
  log_action "Enable service ${name}"
  changes_allowed || return 0
  if [[ "$INIT_SYSTEM" == "systemd" ]] && have_cmd systemctl; then
    systemctl enable "${name}.service"
    return
  fi
  if have_cmd chkconfig; then
    chkconfig "$name" on
  fi
}

svc_disable() {
  local name="$1"
  log_action "Disable service ${name}"
  changes_allowed || return 0
  if [[ "$INIT_SYSTEM" == "systemd" ]] && have_cmd systemctl; then
    systemctl disable "${name}.service"
    return
  fi
  if have_cmd chkconfig; then
    chkconfig "$name" off
  fi
}

svc_start() {
  local name="$1"
  log_action "Start service ${name}"
  changes_allowed || return 0
  if [[ "$INIT_SYSTEM" == "systemd" ]] && have_cmd systemctl; then
    systemctl start "${name}.service"
    return
  fi
  service "$name" start
}

svc_stop() {
  local name="$1"
  log_action "Stop service ${name}"
  changes_allowed || return 0
  if [[ "$INIT_SYSTEM" == "systemd" ]] && have_cmd systemctl; then
    systemctl stop "${name}.service"
    return
  fi
  service "$name" stop
}

svc_restart() {
  local name="$1"
  log_action "Restart service ${name}"
  changes_allowed || return 0
  if [[ "$INIT_SYSTEM" == "systemd" ]] && have_cmd systemctl; then
    systemctl restart "${name}.service"
    return
  fi
  service "$name" restart
}

svc_reload() {
  local name="$1"
  log_action "Reload service ${name}"
  changes_allowed || return 0
  if [[ "$INIT_SYSTEM" == "systemd" ]] && have_cmd systemctl; then
    systemctl reload "${name}.service" 2>/dev/null || systemctl restart "${name}.service"
    return
  fi
  service "$name" reload 2>/dev/null || service "$name" restart
}

svc_status_line() {
  local name="$1"
  local active="inactive"
  local enabled="disabled"
  svc_is_active "$name" && active="active"
  svc_is_enabled "$name" && enabled="enabled"
  printf '%s %s %s' "$name" "$active" "$enabled"
}

is_essential_service() {
  local name="$1"
  local item
  for item in ${ESSENTIAL_SERVICES:-}; do
    [[ "$item" == "$name" ]] && return 0
  done
  return 1
}

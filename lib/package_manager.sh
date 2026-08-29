#!/usr/bin/env bash
# Package manager abstraction. Modules must not call apt/dnf/yum directly.

_pkg_need_mgr() {
  if [[ -z "${PKG_MGR:-}" || "$PKG_MGR" == "unknown" ]]; then
    detect_package_manager
  fi
  if [[ "$PKG_MGR" == "unknown" ]]; then
    die "No supported package manager found (apt, dnf, yum)."
  fi
}

update_package_index() {
  _pkg_need_mgr
  log_action "Refresh package index (${PKG_MGR})"
  changes_allowed || return 0
  case "$PKG_MGR" in
    apt)
      DEBIAN_FRONTEND=noninteractive apt-get update -qq
      ;;
    dnf)
      dnf makecache -q --refresh
      ;;
    yum)
      yum makecache -q
      ;;
    *) die "Unsupported package manager: ${PKG_MGR}" ;;
  esac
}

upgrade_packages() {
  local security_only="${1:-false}"
  _pkg_need_mgr
  if is_true "$security_only"; then
    log_action "Apply security updates (${PKG_MGR})"
  else
    log_action "Apply system updates (${PKG_MGR})"
  fi
  changes_allowed || return 0
  case "$PKG_MGR" in
    apt)
      if is_true "$security_only" && have_cmd unattended-upgrade; then
        DEBIAN_FRONTEND=noninteractive unattended-upgrade -v || \
          DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
      else
        DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
      fi
      ;;
    dnf)
      if is_true "$security_only"; then
        dnf -y upgrade --security || dnf -y upgrade
      else
        dnf -y upgrade
      fi
      ;;
    yum)
      if is_true "$security_only" && yum help upgrade-minimal >/dev/null 2>&1; then
        yum -y --security update || yum -y update
      else
        yum -y update
      fi
      ;;
  esac
}

install_package() {
  local pkg="$1"
  [[ -z "$pkg" ]] && die "install_package requires a package name"
  _pkg_need_mgr
  if is_package_installed "$pkg"; then
    log_info "Package already installed: ${pkg}"
    return 0
  fi
  log_action "Install package: ${pkg}"
  changes_allowed || return 0
  case "$PKG_MGR" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" ;;
    dnf) dnf install -y "$pkg" ;;
    yum) yum install -y "$pkg" ;;
  esac
}

install_packages() {
  local pkg
  for pkg in "$@"; do
    install_package "$pkg"
  done
}

remove_package() {
  local pkg="$1"
  [[ -z "$pkg" ]] && die "remove_package requires a package name"
  _pkg_need_mgr
  if ! is_package_installed "$pkg"; then
    log_info "Package not installed: ${pkg}"
    return 0
  fi
  log_action "Remove package: ${pkg}"
  changes_allowed || return 0
  case "$PKG_MGR" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get remove -y "$pkg" ;;
    dnf) dnf remove -y "$pkg" ;;
    yum) yum remove -y "$pkg" ;;
  esac
}

is_package_installed() {
  local pkg="$1"
  _pkg_need_mgr
  case "$PKG_MGR" in
    apt)
      dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"
      ;;
    dnf)
      dnf list installed "$pkg" >/dev/null 2>&1
      ;;
    yum)
      rpm -q "$pkg" >/dev/null 2>&1
      ;;
    *)
      return 1
      ;;
  esac
}

package_candidate() {
  # Try a list of package names; install the first that exists or is already installed.
  local name
  for name in "$@"; do
    if is_package_installed "$name"; then
      printf '%s' "$name"
      return 0
    fi
  done
  for name in "$@"; do
    if _package_available "$name"; then
      printf '%s' "$name"
      return 0
    fi
  done
  return 1
}

_package_available() {
  local pkg="$1"
  case "$PKG_MGR" in
    apt) apt-cache show "$pkg" >/dev/null 2>&1 ;;
    dnf) dnf list --available "$pkg" >/dev/null 2>&1 ;;
    yum) yum list "$pkg" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

pending_reboot() {
  if [[ -f /var/run/reboot-required ]]; then
    return 0
  fi
  if have_cmd needs-restarting && needs-restarting -r >/dev/null 2>&1; then
    # needs-restarting -r returns 1 when reboot is needed
    return 1
  fi
  if have_cmd needs-restarting; then
    needs-restarting -r >/dev/null 2>&1
    local rc=$?
    [[ $rc -eq 1 ]]
    return
  fi
  return 1
}

os_is_eol() {
  # Best-effort. Never fail the run if detection is incomplete.
  if have_cmd ubuntu-support-status && [[ "$OS_ID" == "ubuntu" ]]; then
    return 1
  fi
  if [[ -r /etc/os-release ]]; then
    local eol=""
    eol="$(. /etc/os-release && printf '%s' "${SUPPORT_END:-${VERSION_CODENAME:-}}")"
    # Informational only; modules report rather than abort.
  fi
  return 1
}

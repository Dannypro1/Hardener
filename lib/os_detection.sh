#!/usr/bin/env bash
# Detect distribution, architecture, package manager, init, firewall, SSH.

detect_os() {
  OS_ARCH="$(uname -m 2>/dev/null || echo unknown)"
  OS_ID=""
  OS_ID_LIKE=""
  OS_VERSION_ID=""
  OS_NAME=""
  OS_PRETTY=""

  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    OS_ID="$(. /etc/os-release && printf '%s' "${ID:-}")"
    OS_ID_LIKE="$(. /etc/os-release && printf '%s' "${ID_LIKE:-}")"
    OS_VERSION_ID="$(. /etc/os-release && printf '%s' "${VERSION_ID:-}")"
    OS_NAME="$(. /etc/os-release && printf '%s' "${NAME:-}")"
    OS_PRETTY="$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-}")"
  elif [[ -r /etc/redhat-release ]]; then
    OS_NAME="$(cat /etc/redhat-release)"
    OS_PRETTY="$OS_NAME"
    if grep -qi centos /etc/redhat-release; then OS_ID="centos"
    elif grep -qi rocky /etc/redhat-release; then OS_ID="rocky"
    elif grep -qi alma /etc/redhat-release; then OS_ID="almalinux"
    elif grep -qi fedora /etc/redhat-release; then OS_ID="fedora"
    else OS_ID="rhel"
    fi
  else
    OS_ID="unknown"
    OS_NAME="Unknown"
    OS_PRETTY="Unknown Linux"
  fi

  OS_ID="$(printf '%s' "$OS_ID" | tr '[:upper:]' '[:lower:]')"
  detect_package_manager
  detect_init_system
  detect_firewall_backend
  detect_ssh_service
  detect_ssh_session
}

detect_package_manager() {
  PKG_MGR=""
  case "$OS_ID" in
    ubuntu|debian)
      PKG_MGR="apt"
      ;;
    fedora)
      PKG_MGR="dnf"
      ;;
    centos|rhel|rocky|almalinux)
      if have_cmd dnf; then
        PKG_MGR="dnf"
      else
        PKG_MGR="yum"
      fi
      ;;
    *)
      if have_cmd apt-get; then PKG_MGR="apt"
      elif have_cmd dnf; then PKG_MGR="dnf"
      elif have_cmd yum; then PKG_MGR="yum"
      else PKG_MGR="unknown"
      fi
      ;;
  esac
}

detect_init_system() {
  INIT_SYSTEM="unknown"
  if [[ -d /run/systemd/system ]] || [[ "$(cat /proc/1/comm 2>/dev/null || true)" == "systemd" ]]; then
    INIT_SYSTEM="systemd"
  elif have_cmd systemctl && systemctl --version >/dev/null 2>&1; then
    INIT_SYSTEM="systemd"
  elif [[ -f /sbin/init ]] && [[ -d /etc/init.d ]]; then
    INIT_SYSTEM="sysv"
  fi
}

detect_firewall_backend() {
  FIREWALL_BACKEND_DETECTED=""
  if [[ -n "${FIREWALL_BACKEND:-}" ]]; then
    FIREWALL_BACKEND_DETECTED="$FIREWALL_BACKEND"
    return 0
  fi

  if have_cmd ufw && ufw status >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -qi "Status: active"; then
      FIREWALL_BACKEND_DETECTED="ufw"
      return 0
    fi
  fi
  if have_cmd firewall-cmd; then
    if firewall-cmd --state >/dev/null 2>&1; then
      FIREWALL_BACKEND_DETECTED="firewalld"
      return 0
    fi
  fi
  if have_cmd nft && nft list ruleset >/dev/null 2>&1; then
    if nft list ruleset 2>/dev/null | grep -q "table"; then
      FIREWALL_BACKEND_DETECTED="nftables"
      return 0
    fi
  fi

  # Prefer the distro default when nothing is active.
  case "$OS_ID" in
    ubuntu|debian) FIREWALL_BACKEND_DETECTED="ufw" ;;
    fedora|centos|rhel|rocky|almalinux) FIREWALL_BACKEND_DETECTED="firewalld" ;;
    *) FIREWALL_BACKEND_DETECTED="nftables" ;;
  esac
}

detect_ssh_service() {
  SSH_SERVICE=""
  SSH_PORT_CURRENT="22"

  if [[ "$INIT_SYSTEM" == "systemd" ]] && have_cmd systemctl; then
    if systemctl list-unit-files ssh.service >/dev/null 2>&1 && \
       systemctl cat ssh.service >/dev/null 2>&1; then
      SSH_SERVICE="ssh"
    elif systemctl list-unit-files sshd.service >/dev/null 2>&1 && \
         systemctl cat sshd.service >/dev/null 2>&1; then
      SSH_SERVICE="sshd"
    fi
  fi

  if [[ -z "$SSH_SERVICE" ]]; then
    if [[ -f /lib/systemd/system/ssh.service || -f /usr/lib/systemd/system/ssh.service ]]; then
      SSH_SERVICE="ssh"
    else
      SSH_SERVICE="sshd"
    fi
  fi

  local port
  port="$(detect_listening_ssh_port || true)"
  if [[ -n "$port" ]]; then
    SSH_PORT_CURRENT="$port"
  elif [[ -n "${SSH_PORT:-}" ]]; then
    SSH_PORT_CURRENT="$SSH_PORT"
  fi
}

detect_listening_ssh_port() {
  local port=""

  # Prefer the port of the current SSH session — this is the lockout-safety source of truth.
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    local sp
    sp="$(printf '%s' "$SSH_CONNECTION" | awk '{print $4}')"
    if [[ "$sp" =~ ^[0-9]+$ ]]; then
      printf '%s' "$sp"
      return 0
    fi
  fi

  if [[ -r /etc/ssh/sshd_config ]]; then
    port="$(awk '/^[[:space:]]*Port[[:space:]]+/ {print $2; exit}' /etc/ssh/sshd_config)"
    if [[ -z "$port" && -d /etc/ssh/sshd_config.d ]]; then
      port="$(grep -hE '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{print $2; exit}')"
    fi
  fi
  if [[ -n "$port" ]]; then
    printf '%s' "$port"
    return 0
  fi

  if have_cmd ss && ss -lntH 2>/dev/null | grep -q ':22[[:space:]]'; then
    printf '22'
    return 0
  fi
  printf '22'
}

detect_ssh_session() {
  IS_SSH_SESSION="false"
  CURRENT_SSH_USER="${SUDO_USER:-${USER:-}}"
  CURRENT_SSH_TTY="$(tty 2>/dev/null || true)"
  if [[ -n "${SSH_CONNECTION:-}" || -n "${SSH_CLIENT:-}" || -n "${SSH_TTY:-}" ]]; then
    IS_SSH_SESSION="true"
  fi
}

detect_environment() {
  detect_os
  log_info "Detected OS: ${OS_PRETTY:-$OS_NAME} (${OS_ID} ${OS_VERSION_ID})"
  log_info "Architecture: ${OS_ARCH}"
  log_info "Package manager: ${PKG_MGR}"
  log_info "Init system: ${INIT_SYSTEM}"
  log_info "Firewall backend: ${FIREWALL_BACKEND_DETECTED}"
  log_info "SSH service: ${SSH_SERVICE} (port ${SSH_PORT_CURRENT})"
  if [[ "$IS_SSH_SESSION" == "true" ]]; then
    log_warning "Remote SSH session detected as ${CURRENT_SSH_USER}. Lockout protections are active."
  fi
}

os_is_supported() {
  local id
  for id in $SUPPORTED_OS_IDS; do
    [[ "$OS_ID" == "$id" ]] && return 0
  done
  # Also accept ID_LIKE matches for derivatives.
  case " ${OS_ID_LIKE} " in
    *" debian "*|*" ubuntu "*) return 0 ;;
    *" rhel "*|*" fedora "*|*" centos "*) return 0 ;;
  esac
  return 1
}

os_family() {
  case "$OS_ID" in
    ubuntu|debian) printf 'debian' ;;
    fedora|centos|rhel|rocky|almalinux) printf 'rhel' ;;
    *)
      case " ${OS_ID_LIKE} " in
        *" debian "*|*" ubuntu "*) printf 'debian' ;;
        *) printf 'rhel' ;;
      esac
      ;;
  esac
}

display_detected_os() {
  print_banner
  ui_box_top
  ui_box_center "DETECTED OPERATING SYSTEM"
  ui_box_sep
  ui_box_row ""
  ui_box_row "  ✓  ${OS_PRETTY:-$OS_NAME}"
  ui_box_row ""
  ui_box_kv "Architecture" "${OS_ARCH}"
  ui_box_kv "Package manager" "${PKG_MGR}"
  ui_box_kv "Init system" "${INIT_SYSTEM}"
  ui_box_kv "Firewall" "${FIREWALL_BACKEND_DETECTED}"
  ui_box_kv "SSH service" "${SSH_SERVICE}  (port ${SSH_PORT_CURRENT})"
  if ! os_is_supported; then
    ui_box_sep
    ui_box_row "  This distribution is not in the supported list."
    ui_box_row "  Ubuntu · Debian · Fedora · CentOS · RHEL · Rocky · Alma"
  fi
  ui_box_bottom
  printf '\n'
}

manual_os_select() {
  printf '\n'
  ui_box_top
  ui_box_center "SELECT OPERATING SYSTEM"
  ui_box_sep
  ui_box_row " [1]  Ubuntu          [5]  RHEL"
  ui_box_row " [2]  Debian          [6]  Rocky Linux"
  ui_box_row " [3]  Fedora          [7]  AlmaLinux"
  ui_box_row " [4]  CentOS"
  ui_box_bottom
  printf '\n'
  local choice
  choice="$(prompt_choice "Choice" 1 7)"
  case "$choice" in
    1) OS_ID="ubuntu"; OS_NAME="Ubuntu"; PKG_MGR="apt" ;;
    2) OS_ID="debian"; OS_NAME="Debian"; PKG_MGR="apt" ;;
    3) OS_ID="fedora"; OS_NAME="Fedora"; PKG_MGR="dnf" ;;
    4) OS_ID="centos"; OS_NAME="CentOS"; PKG_MGR="$(have_cmd dnf && echo dnf || echo yum)" ;;
    5) OS_ID="rhel"; OS_NAME="Red Hat Enterprise Linux"; PKG_MGR="$(have_cmd dnf && echo dnf || echo yum)" ;;
    6) OS_ID="rocky"; OS_NAME="Rocky Linux"; PKG_MGR="dnf" ;;
    7) OS_ID="almalinux"; OS_NAME="AlmaLinux"; PKG_MGR="dnf" ;;
  esac
  OS_PRETTY="${OS_NAME} (manually selected)"
  detect_init_system
  detect_firewall_backend
  detect_ssh_service
  log_warning "Administrator overrode OS detection: ${OS_PRETTY}"
}

confirm_detected_os() {
  display_detected_os
  if is_true "$NON_INTERACTIVE"; then
    if ! os_is_supported; then
      die "Unsupported OS in non-interactive mode: ${OS_ID}"
    fi
    CONFIRMED_OS="true"
    return 0
  fi
  printf '%s  Is this correct?%s\n\n' "${C_BGREEN}" "${C_RESET}"
  ui_menu_item "1" "Yes, continue"
  ui_menu_item "2" "Select manually"
  printf '\n'
  local choice
  choice="$(prompt_choice "Choice" 1 2)"
  if [[ "$choice" == "2" ]]; then
    manual_os_select
  fi
  CONFIRMED_OS="true"
}

probe_security_tools() {
  local tools=()
  have_cmd sshd && tools+=("sshd")
  have_cmd ufw && tools+=("ufw")
  have_cmd firewall-cmd && tools+=("firewalld")
  have_cmd nft && tools+=("nftables")
  have_cmd fail2ban-client && tools+=("fail2ban")
  have_cmd auditctl && tools+=("auditd")
  have_cmd aide && tools+=("aide")
  have_cmd wazuh-control && tools+=("wazuh")
  have_cmd google-authenticator && tools+=("google-authenticator")
  printf '%s' "${tools[*]-none}"
}

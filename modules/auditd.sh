#!/usr/bin/env bash
# auditd baseline. Single managed rules file, validated after write.

_auditd_pkg() {
  case "$(os_family)" in
    debian) printf 'auditd' ;;
    rhel)   printf 'audit' ;;
    *)      printf 'auditd' ;;
  esac
}

_auditd_rules() {
  cat <<EOF
# Managed by Server Hardener — do not duplicate these keys elsewhere.
-D
-b ${AUDITD_BACKLOG_LIMIT:-8192}
-f 1

# Time
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Identity / accounts
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Hostname / network
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale

# Privilege / sudo
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /var/log/sudo.log -p wa -k sudo-log

# SSH
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd

# Login / session
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# Mandatory access / MAC
-w /etc/selinux/ -p wa -k MAC-policy
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# Privilege escalation syscalls
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid,setresuid,setresgid -F auid>=1000 -F auid!=4294967295 -k priv-esc
-a always,exit -F arch=b32 -S setuid,setgid,setreuid,setregid,setresuid,setresgid -F auid>=1000 -F auid!=4294967295 -k priv-esc

# Privileged commands (euid=0)
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands
-a always,exit -F arch=b32 -S execve -F euid=0 -k root_commands

# Unsuccessful file access
-a always,exit -F arch=b64 -S open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module,finit_module -k modules

-e 2
EOF
}

module_auditd_audit() {
  if have_cmd auditctl && svc_is_active auditd; then
    record_finding "Auditd" "PASS" "INFO" "auditd is running" "active" "active" "No action" "CIS 4.1 / NIST AU-2"
  elif have_cmd auditctl; then
    record_finding "Auditd" "WARN" "MEDIUM" "auditd installed but not running" "inactive" "active" \
      "Enable and start auditd" "CIS 4.1.1"
  else
    record_finding "Auditd" "WARN" "MEDIUM" "auditd is not installed" "missing" "installed and running" \
      "Apply the auditd module" "CIS 4.1.1"
  fi
  if [[ -f "${AUDITD_RULES_FILE:-/etc/audit/rules.d/99-server-hardening.rules}" ]]; then
    record_finding "Audit Rules" "PASS" "INFO" "Managed rules file present" \
      "${AUDITD_RULES_FILE}" "managed rules" "No action" "CIS 4.1"
  fi
}

module_auditd_plan() {
  printf '  Install %s if missing\n' "$(_auditd_pkg)"
  printf '  Write %s\n' "${AUDITD_RULES_FILE:-/etc/audit/rules.d/99-server-hardening.rules}"
  printf '  Enable auditd; validate with augenrules/auditctl\n'
}

module_auditd_apply() {
  if is_false "${AUDITD_ENABLED:-true}"; then
    log_info "auditd disabled in configuration"
    return 0
  fi
  install_package "$(_auditd_pkg)" || log_warning "Could not install auditd package"

  backup_paths auditd /etc/audit /etc/audit/rules.d
  local file="${AUDITD_RULES_FILE:-/etc/audit/rules.d/99-server-hardening.rules}"
  write_managed_file "$file" 0640 auditd < <(_auditd_rules)

  if [[ -f /etc/audit/auditd.conf ]]; then
    backup_file /etc/audit/auditd.conf auditd
    if changes_allowed; then
      sed -i -E "s/^max_log_file[[:space:]]*=.*/max_log_file = ${AUDITD_MAX_LOG_FILE:-50}/" /etc/audit/auditd.conf
      sed -i -E "s/^num_logs[[:space:]]*=.*/num_logs = ${AUDITD_NUM_LOGS:-5}/" /etc/audit/auditd.conf
      sed -i -E "s/^max_log_file_action[[:space:]]*=.*/max_log_file_action = ${AUDITD_MAX_LOG_ACTION:-rotate}/" /etc/audit/auditd.conf
    fi
  fi

  if have_cmd augenrules && changes_allowed; then
    augenrules --load >/dev/null 2>&1 || log_warning "augenrules --load reported issues"
  fi
  svc_enable auditd || true
  svc_start auditd || svc_restart auditd || true
}

module_auditd_validate() {
  validate_audit_rules || true
  if have_cmd auditctl && changes_allowed; then
    auditctl -s >/dev/null 2>&1 || log_warning "auditctl -s failed"
  fi
}

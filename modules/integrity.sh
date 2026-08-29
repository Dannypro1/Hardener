#!/usr/bin/env bash
# Optional AIDE file integrity monitoring. Never overwrites an existing database.

_aide_pkg() {
  printf 'aide'
}

_aide_db() {
  if [[ -f /var/lib/aide/aide.db.gz ]]; then
    printf '/var/lib/aide/aide.db.gz'
  elif [[ -f /var/lib/aide/aide.db ]]; then
    printf '/var/lib/aide/aide.db'
  elif [[ -f /var/lib/aide/aide.db.new.gz ]]; then
    printf '/var/lib/aide/aide.db.new.gz'
  else
    printf ''
  fi
}

module_integrity_audit() {
  if have_cmd aide; then
    local db
    db="$(_aide_db)"
    if [[ -n "$db" ]]; then
      record_finding "Integrity Monitoring" "PASS" "INFO" \
        "AIDE is installed and a database exists" "$db" "initialized database" \
        "Run aide --check on a schedule" "CIS 1.4 / CIS Control 3"
    else
      record_finding "Integrity Monitoring" "WARN" "MEDIUM" \
        "AIDE is installed but no database was found" "no db" "initialized db" \
        "Initialize with aide --init and install the new database" "CIS 1.4.1"
    fi
  else
    record_finding "Integrity Monitoring" "WARN" "LOW" \
      "AIDE is not installed" "missing" "optional FIM" \
      "Apply the integrity module to install AIDE" "CIS 1.4"
  fi
}

module_integrity_plan() {
  printf '  Install AIDE if missing\n'
  printf '  Initialize a database only when none exists\n'
  printf '  Never overwrite an existing AIDE database\n'
}

module_integrity_apply() {
  install_package "$(_aide_pkg)" || {
    log_warning "AIDE package not available"
    return 0
  }

  local db
  db="$(_aide_db)"
  if [[ -n "$db" ]]; then
    log_warning "Existing AIDE database found at ${db}; not overwritten"
    if prompt_yes_no "Run an integrity check now?" "n"; then
      log_action "aide --check"
      if changes_allowed; then
        aide --check || aide -C || true
      fi
    fi
    return 0
  fi

  if prompt_yes_no "Initialize a new AIDE database? This can take several minutes" "n"; then
    log_action "aide --init"
    if changes_allowed; then
      aide --init || aideinit || true
      if [[ -f /var/lib/aide/aide.db.new.gz && ! -f /var/lib/aide/aide.db.gz ]]; then
        cp -a /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
        log_success "Installed new AIDE database"
      fi
    fi
  fi
}

module_integrity_validate() {
  have_cmd aide || return 0
  return 0
}

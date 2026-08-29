#!/usr/bin/env bash
# Visible, per-control customization. Nothing is applied until the administrator
# sees the ON/OFF list and confirms. Flags are session variables, not hidden jobs.

# id|module|variable|label
DEFENSE_CATALOG=(
  "lock_empty|users|USER_LOCK_EMPTY_PASSWORDS|Lock empty-password accounts"
  "tighten_homes|users|USER_TIGHTEN_HOMES|Tighten home directories to 0750"
  "umask|users|USER_SET_UMASK|Set umask 027 for new files"
  "tmout|users|USER_SET_TMOUT|Set shell idle timeout (TMOUT)"
  "nologin_sys|users|USER_NOLOGIN_SYSTEM|Force nologin on known system accounts"
  "aging|passwords|PW_APPLY_AGING|Set password aging in login.defs"
  "pwquality|passwords|PW_APPLY_QUALITY|Configure password quality (pwquality)"
  "faillock|passwords|PW_APPLY_FAILLOCK|Configure faillock after failed logins"
  "ssh_root|ssh|SSH_DISABLE_ROOT_LOGIN|Disable SSH root login"
  "ssh_pass|ssh|SSH_DISABLE_PASSWORD_AUTH|Disable SSH password authentication"
  "ssh_algo|ssh|SSH_HARDEN_ALGORITHMS|Harden SSH key-exchange algorithms"
  "fw_deny|firewall|FIREWALL_DEFAULT_DENY|Firewall default-deny inbound"
  "auto_svc|services|SERVICES_AUTO_DISABLE_DANGEROUS|Disable telnet/rsh/NIS/TFTP"
  "sticky|filesystem|FS_HARDEN_TMP_STICKY|Sticky bit on /tmp and /var/tmp"
  "shm|filesystem|FS_HARDEN_SHM|Harden /dev/shm (nodev,nosuid,noexec)"
  "tmp_noexec|filesystem|FS_TMP_NOEXEC|Add noexec on /tmp (can break installers)"
  "blacklist_net|kernel|KERNEL_BLACKLIST_UNCOMMON|Blacklist unused network/FS modules"
  "blacklist_usb|kernel|KERNEL_BLACKLIST_USB|Blacklist USB storage"
  "net_sysctl|network|NETWORK_APPLY_SYSCTL|Apply network stack sysctl defenses"
  "no_ipv6|network|NETWORK_DISABLE_IPV6|Disable IPv6"
  "f2b|fail2ban|FAIL2BAN_ENABLED|Enable Fail2ban SSH jail"
)

module_is_selected() {
  local want="$1"
  local m
  for m in "${SELECTED_MODULES[@]+"${SELECTED_MODULES[@]}"}"; do
    [[ "$m" == "$want" ]] && return 0
  done
  return 1
}

_defense_var() { printf '%s' "$1" | cut -d'|' -f3; }
_defense_mod() { printf '%s' "$1" | cut -d'|' -f2; }
_defense_label() { printf '%s' "$1" | cut -d'|' -f4; }

defense_flag_on() {
  local var="$1"
  is_true "${!var:-false}"
}

set_defense_flag() {
  local var="$1"
  local value="$2"
  printf -v "$var" '%s' "$value"
  export "${var?}"
}

toggle_defense_flag() {
  local var="$1"
  if defense_flag_on "$var"; then
    set_defense_flag "$var" "false"
  else
    set_defense_flag "$var" "true"
  fi
}

relevant_defenses() {
  local entry
  for entry in "${DEFENSE_CATALOG[@]}"; do
    if module_is_selected "$(_defense_mod "$entry")"; then
      printf '%s\n' "$entry"
    fi
  done
}

print_defense_summary() {
  local entries=()
  mapfile -t entries < <(relevant_defenses)
  printf '\n'
  ui_box_top
  ui_box_center "DEFENSE OPTIONS  ·  your choices"
  ui_box_sep
  if [[ ${#entries[@]} -eq 0 ]]; then
    ui_box_row "  No tunable defenses for the selected modules."
    ui_box_bottom
    return 0
  fi
  local i=1
  local entry var label state mark
  for entry in "${entries[@]}"; do
    var="$(_defense_var "$entry")"
    label="$(_defense_label "$entry")"
    if defense_flag_on "$var"; then
      state="ON "
      mark="✓"
    else
      state="OFF"
      mark="·"
    fi
    ui_box_row "$(printf ' [%2d]  %s  %-3s  %s' "$i" "$mark" "$state" "$label")"
    i=$((i + 1))
  done
  ui_box_sep
  ui_box_row "  ON  = will be applied     OFF = left unchanged"
  ui_box_bottom
  printf '\n'
}

announce_defense() {
  local var="$1"
  local label="$2"
  if defense_flag_on "$var"; then
    log_info "Will apply: ${label}"
  else
    log_info "Skipped (turned off): ${label}"
  fi
}

parse_set_option() {
  local spec="$1"
  if [[ "$spec" != *=* ]]; then
    die "--set requires NAME=value"
  fi
  local var="${spec%%=*}"
  local val="${spec#*=}"
  case "$var" in
    USER_*|PW_*|SSH_*|FS_*|KERNEL_*|NETWORK_*|SERVICES_*|FAIL2BAN_*|FIREWALL_*|MFA_*|WAZUH_*|AUTO_REBOOT|SYSCTL_*)
      set_defense_flag "$var" "$val"
      log_info "Set ${var}=${val}"
      ;;
    *)
      die "Unknown or unsupported --set variable: ${var}"
      ;;
  esac
}

customize_defenses() {
  if is_audit_mode; then
    print_defense_summary
    return 0
  fi
  if is_true "$NON_INTERACTIVE"; then
    print_defense_summary
    return 0
  fi

  while true; do
    print_defense_summary
    printf '%s  Toggle by number (e.g. 1,4,7)  ·  Enter to keep these choices%s\n' \
      "${C_GREEN}" "${C_RESET}"
    local raw
    raw="$(prompt_read "Toggle or Enter" "")"
    if [[ -z "$raw" ]]; then
      break
    fi
    local entries=()
    mapfile -t entries < <(relevant_defenses)
    local token idx
    while IFS= read -r token; do
      token="$(trim "$token")"
      [[ -z "$token" ]] && continue
      if [[ ! "$token" =~ ^[0-9]+$ ]]; then
        log_warning "Not a number: ${token}"
        continue
      fi
      idx=$((token - 1))
      if (( idx < 0 || idx >= ${#entries[@]} )); then
        log_warning "Out of range: ${token}"
        continue
      fi
      toggle_defense_flag "$(_defense_var "${entries[$idx]}")"
    done < <(split_list "$raw")
  done
  print_defense_summary
}

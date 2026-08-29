#!/usr/bin/env bash
set -Eeuo pipefail
# shellcheck source=_helpers.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_helpers.sh"

printf 'test_os_detection\n'

detect_package_manager
if in_list "$PKG_MGR" apt dnf yum unknown; then rc=0; else rc=1; fi
assert_true "package manager is apt, dnf, yum, or unknown" "$rc"

detect_init_system
if [[ -n "$INIT_SYSTEM" ]]; then rc=0; else rc=1; fi
assert_true "init system string is set" "$rc"

OS_ID="ubuntu"
assert_eq "$(os_family)" "debian" "ubuntu -> debian family"
OS_ID="rocky"
assert_eq "$(os_family)" "rhel" "rocky -> rhel family"
OS_ID="debian"
assert_eq "$(os_family)" "debian" "debian -> debian family"
OS_ID="almalinux"
assert_eq "$(os_family)" "rhel" "almalinux -> rhel family"

OS_ID="fedora"
if os_is_supported; then rc=0; else rc=1; fi
assert_true "fedora is supported" "$rc"

OS_ID="not-a-real-distro"
OS_ID_LIKE=""
if os_is_supported; then rc=0; else rc=1; fi
assert_false "unknown id is unsupported" "$rc"

if is_known_module ssh; then rc=0; else rc=1; fi
assert_true "ssh is a known module" "$rc"
if is_known_module notamodule; then rc=0; else rc=1; fi
assert_false "notamodule is unknown" "$rc"

parse_module_selection "1,5"
assert_eq "${SELECTED_MODULES[0]}" "updates" "menu index 1 is updates"
assert_eq "${SELECTED_MODULES[1]}" "ssh" "menu index 5 is ssh"

test_summary test_os_detection

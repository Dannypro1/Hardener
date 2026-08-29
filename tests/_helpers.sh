#!/usr/bin/env bash
# Shared test bootstrap. Safe to source from any test_*.sh.
set -Eeuo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARDENER_ROOT="$(cd "${TEST_DIR}/.." && pwd)"
export HARDENER_ROOT
export NON_INTERACTIVE=true
export MODE=audit
export REQUIRE_CONFIRMATION=false

# shellcheck source=../lib/common.sh
source "${HARDENER_ROOT}/lib/common.sh"
# shellcheck source=../lib/logging.sh
source "${HARDENER_ROOT}/lib/logging.sh"
# shellcheck source=../lib/os_detection.sh
source "${HARDENER_ROOT}/lib/os_detection.sh"
# shellcheck source=../lib/package_manager.sh
source "${HARDENER_ROOT}/lib/package_manager.sh"
# shellcheck source=../lib/prompt.sh
source "${HARDENER_ROOT}/lib/prompt.sh"
# shellcheck source=../lib/backup.sh
source "${HARDENER_ROOT}/lib/backup.sh"
# shellcheck source=../lib/validation.sh
source "${HARDENER_ROOT}/lib/validation.sh"
# shellcheck source=../lib/service_manager.sh
source "${HARDENER_ROOT}/lib/service_manager.sh"

load_all_config
FINDINGS_FILE="$(mktemp)"
: > "$FINDINGS_FILE"

PASS=0
FAIL=0

assert_eq() {
  local got="$1"
  local want="$2"
  local msg="${3:-assertion}"
  if [[ "$got" == "$want" ]]; then
    PASS=$((PASS + 1))
    printf '  PASS  %s\n' "$msg"
  else
    FAIL=$((FAIL + 1))
    printf '  FAIL  %s (got %q want %q)\n' "$msg" "$got" "$want"
  fi
}

assert_true() {
  local msg="$1"
  if [ "$2" = "0" ]; then
    PASS=$((PASS + 1))
    printf '  PASS  %s\n' "$msg"
  else
    FAIL=$((FAIL + 1))
    printf '  FAIL  %s\n' "$msg"
  fi
}

assert_false() {
  local msg="$1"
  if [ "$2" != "0" ]; then
    PASS=$((PASS + 1))
    printf '  PASS  %s\n' "$msg"
  else
    FAIL=$((FAIL + 1))
    printf '  FAIL  %s (expected failure)\n' "$msg"
  fi
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    PASS=$((PASS + 1))
    printf '  PASS  %s\n' "$msg"
  else
    FAIL=$((FAIL + 1))
    printf '  FAIL  %s (missing %q)\n' "$msg" "$needle"
  fi
}

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    PASS=$((PASS + 1))
    printf '  PASS  %s\n' "$msg"
  else
    FAIL=$((FAIL + 1))
    printf '  FAIL  %s (unexpected %q)\n' "$msg" "$needle"
  fi
}


test_summary() {
  printf '\n%s: %s passed, %s failed\n' "${1:-tests}" "$PASS" "$FAIL"
  [[ "$FAIL" -eq 0 ]]
}

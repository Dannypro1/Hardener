#!/usr/bin/env bash
# Run the unit suite. Intended for Linux or WSL with Bash 4+.
set -Eeuo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
failed=0

run_one() {
  local script="$1"
  printf '\n======== %s ========\n' "$(basename "$script")"
  if bash "$script"; then
    printf 'OK\n'
  else
    printf 'FAILED\n'
    failed=$((failed + 1))
  fi
}

run_one "${TEST_DIR}/test_os_detection.sh"
run_one "${TEST_DIR}/test_ssh.sh"
run_one "${TEST_DIR}/test_firewall.sh"
run_one "${TEST_DIR}/test_pam.sh"

if [[ "$failed" -eq 0 ]]; then
  printf '\nAll test files passed.\n'
  exit 0
fi
printf '\n%s test file(s) failed.\n' "$failed"
exit 1

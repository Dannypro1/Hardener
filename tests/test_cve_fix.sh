#!/usr/bin/env bash
# Unit tests for the CVE fix module and scripts.
set -Eeuo pipefail

# shellcheck source=_helpers.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_helpers.sh"
# shellcheck source=../modules/cve_fix.sh
source "${HARDENER_ROOT}/modules/cve_fix.sh"

printf 'test_cve_fix\n'

# Test 1: cve_fix is in MODULE_CATALOG
if is_known_module cve_fix; then rc=0; else rc=1; fi
assert_true "cve_fix is recognized as a known module" "$rc"

# Test 2: cve-fixing/cve-fix.sh exists
if [[ -f "${HARDENER_ROOT}/cve-fixing/cve-fix.sh" ]]; then rc=0; else rc=1; fi
assert_true "cve-fix.sh exists" "$rc"

# Test 3: assessment summary data exists and is non-empty
if [[ -s "${HARDENER_ROOT}/cve-fixing/data/assessment_summary.json" ]]; then rc=0; else rc=1; fi
assert_true "assessment_summary.json exists and is populated" "$rc"

# Test 4: active CVEs JSON exists and has content
if [[ -s "${HARDENER_ROOT}/cve-fixing/data/active_cves.json" ]]; then rc=0; else rc=1; fi
assert_true "active_cves.json exists and is populated" "$rc"

# Test 5: cve_remediation_matrix.csv exists
if [[ -s "${HARDENER_ROOT}/cve-fixing/data/cve_remediation_matrix.csv" ]]; then rc=0; else rc=1; fi
assert_true "cve_remediation_matrix.csv exists" "$rc"

# Test 6: cve_fix module hooks are defined
if declare -F module_cve_fix_audit >/dev/null; then rc=0; else rc=1; fi
assert_true "module_cve_fix_audit hook exists" "$rc"
if declare -F module_cve_fix_plan >/dev/null; then rc=0; else rc=1; fi
assert_true "module_cve_fix_plan hook exists" "$rc"
if declare -F module_cve_fix_apply >/dev/null; then rc=0; else rc=1; fi
assert_true "module_cve_fix_apply hook exists" "$rc"
if declare -F module_cve_fix_validate >/dev/null; then rc=0; else rc=1; fi
assert_true "module_cve_fix_validate hook exists" "$rc"

# Test 7: cve-fix.sh --help exits with 0
if bash "${HARDENER_ROOT}/cve-fixing/cve-fix.sh" --help >/dev/null 2>&1; then rc=0; else rc=1; fi
assert_true "cve-fix.sh --help executes cleanly" "$rc"

test_summary "test_cve_fix"

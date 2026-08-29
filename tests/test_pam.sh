#!/usr/bin/env bash
set -Eeuo pipefail
# shellcheck source=_helpers.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_helpers.sh"
# shellcheck source=../modules/pam_mfa.sh
source "${HARDENER_ROOT}/modules/pam_mfa.sh"

printf 'test_pam\n'

OS_ID="ubuntu"
assert_eq "$(_mfa_package_name)" "libpam-google-authenticator" "Debian family PAM package"

OS_ID="rhel"
assert_eq "$(_mfa_package_name)" "google-authenticator" "RHEL family PAM package"

OS_ID="rocky"
assert_eq "$(_mfa_package_name)" "google-authenticator" "Rocky PAM package"

line="$(_mfa_pam_line)"
assert_contains "$line" "pam_google_authenticator.so" "PAM line references google-authenticator"
assert_contains "$line" "nullok" "default PAM line includes nullok"

MFA_NULLOK=false
line="$(_mfa_pam_line)"
assert_not_contains "$line" "nullok" "nullok omitted when MFA_NULLOK=false"

redacted="$(redact_secrets 'WAZUH_REGISTRATION_PASSWORD=supersecret')"
assert_contains "$redacted" "REDACTED" "registration password is redacted"
assert_not_contains "$redacted" "supersecret" "raw secret is not present after redaction"

test_summary test_pam

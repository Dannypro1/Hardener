#!/usr/bin/env bash
# Wrapper so the pam_mfa module loads a dedicated check file.

# shellcheck source=pam_check.sh
source "${CHECK_DIR}/pam_check.sh"

check_pam_mfa() {
  check_pam
}

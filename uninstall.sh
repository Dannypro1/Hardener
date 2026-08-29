#!/usr/bin/env bash
# Remove the installed toolkit. Does not undo hardening; use --rollback first.
set -Eeuo pipefail

PREFIX="${PREFIX:-/opt/server-hardener}"
BIN_LINK="${BIN_LINK:-/usr/local/sbin/harden}"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "uninstall.sh must be run as root" >&2
  exit 1
fi

echo "This removes ${PREFIX} and ${BIN_LINK}."
echo "It does not revert SSH, firewall, PAM, or other hardened settings."
echo "Run: sudo ${PREFIX}/harden.sh --rollback   first if you need that."
read -r -p "Continue? [y/N] " reply
case "$reply" in
  y|Y|yes) ;;
  *) echo "Cancelled"; exit 0 ;;
esac

rm -f "$BIN_LINK"
if [[ -d "$PREFIX" ]]; then
  rm -rf "$PREFIX"
fi
echo "Uninstalled."

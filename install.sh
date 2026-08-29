#!/usr/bin/env bash
# Install Server Hardener onto the local system (files only — no hardening).
set -Eeuo pipefail

HARDENER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-/opt/server-hardener}"
BIN_LINK="${BIN_LINK:-/usr/local/sbin/harden}"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "install.sh must be run as root" >&2
  exit 1
fi

mkdir -p "$PREFIX"
# Copy the toolkit without runtime data from a previous copy.
rsync -a --delete \
  --exclude 'logs/*' --exclude 'backups/*' --exclude 'reports/*' \
  --exclude '.git' \
  "${HARDENER_ROOT}/" "${PREFIX}/" 2>/dev/null || {
  mkdir -p "${PREFIX}"
  cp -a "${HARDENER_ROOT}/." "${PREFIX}/"
}

chmod 0750 "$PREFIX"
chmod 0755 "${PREFIX}/harden.sh" "${PREFIX}/install.sh" "${PREFIX}/uninstall.sh"
find "${PREFIX}/lib" "${PREFIX}/modules" "${PREFIX}/checks" "${PREFIX}/tests" \
  -type f -name '*.sh' -exec chmod 0755 {} \;

ln -sfn "${PREFIX}/harden.sh" "$BIN_LINK"
mkdir -p "${PREFIX}/logs" "${PREFIX}/backups" "${PREFIX}/reports"
chmod 0750 "${PREFIX}/logs" "${PREFIX}/backups" "${PREFIX}/reports"

echo "Installed to ${PREFIX}"
echo "Launcher: ${BIN_LINK}"
echo "Run: sudo harden   or   sudo ${PREFIX}/harden.sh"

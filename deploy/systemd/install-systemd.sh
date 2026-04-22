#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

BINARY_SRC="${1:-./dist/almighty-blocker-linux-amd64}"
BINARY_DST="/usr/local/bin/almighty-blocker"
UNIT_SRC="${2:-./deploy/systemd/almighty-blocker.service}"
UNIT_DST="/etc/systemd/system/almighty-blocker.service"
STATE_DIR="/var/lib/almighty-blocker"

install -D -m 0755 "${BINARY_SRC}" "${BINARY_DST}"
install -D -m 0644 "${UNIT_SRC}" "${UNIT_DST}"
mkdir -p "${STATE_DIR}"

systemctl daemon-reload
systemctl enable almighty-blocker.service
systemctl restart almighty-blocker.service
systemctl status --no-pager almighty-blocker.service

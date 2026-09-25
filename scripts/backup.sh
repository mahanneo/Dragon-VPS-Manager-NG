#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root."; exit 1; }
APP=/opt/makia-vps-manager
OUT_DIR=/var/backups/makia-vps-manager
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 "$OUT_DIR"
[[ -d "$APP/data" ]] || { echo "No Makia data directory found."; exit 1; }
tar -C "$APP" -czf "$OUT_DIR/makia-data-$STAMP.tar.gz" data
chmod 0600 "$OUT_DIR/makia-data-$STAMP.tar.gz"
echo "$OUT_DIR/makia-data-$STAMP.tar.gz"

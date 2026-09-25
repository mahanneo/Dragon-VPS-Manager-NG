#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root."; exit 1; }
APP=/opt/dragon-vps-manager-ng
OUT_DIR=/var/backups/dragon-vps-manager-ng
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 "$OUT_DIR"
[[ -d "$APP/data" ]] || { echo "No Dragon data directory found."; exit 1; }
tar -C "$APP" -czf "$OUT_DIR/dragon-data-$STAMP.tar.gz" data
chmod 0600 "$OUT_DIR/dragon-data-$STAMP.tar.gz"
echo "$OUT_DIR/dragon-data-$STAMP.tar.gz"

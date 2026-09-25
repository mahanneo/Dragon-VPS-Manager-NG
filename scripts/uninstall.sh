#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root."; exit 1; }
APP=/opt/dragon-vps-manager-ng
if [[ -d "$APP/data" ]]; then
  BACKUP="$(/usr/local/sbin/dragon-backup 2>/dev/null || true)"
  [[ -n "$BACKUP" ]] && echo "Backup created: $BACKUP"
fi
systemctl disable --now dragon-vps-manager 2>/dev/null || true
rm -f /etc/systemd/system/dragon-vps-manager.service
rm -f /etc/nginx/sites-enabled/dragon-vps-manager /etc/nginx/sites-available/dragon-vps-manager
rm -f /usr/local/sbin/dragon-update /usr/local/sbin/dragon-backup /usr/local/sbin/dragon-uninstall
systemctl daemon-reload
nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
rm -rf "$APP"
echo "Dragon VPS Manager NG removed. Backups under /var/backups/dragon-vps-manager-ng are preserved."

#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root."; exit 1; }
REPO="mahanneo/Makia-VPS-Manager"
REF="${MAKIA_REF:-${DRAGON_REF:-main}}"
APP=/opt/dragon-vps-manager-ng
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

[[ -d "$APP" ]] || { echo "Dragon VPS Manager NG is not installed."; exit 1; }
BACKUP="$(/usr/local/sbin/dragon-backup)"
echo "Backup created: $BACKUP"

curl -fL --retry 3 "https://github.com/${REPO}/archive/refs/heads/${REF}.tar.gz" -o "$TMP/source.tar.gz"
tar -xzf "$TMP/source.tar.gz" -C "$TMP"
SRC="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d -name 'Makia-VPS-Manager-*' | head -n1)"
[[ -n "$SRC" ]] || { echo "Unable to locate extracted source."; exit 1; }

systemctl stop dragon-vps-manager
rm -rf "$APP/app"
cp -a "$SRC/app" "$APP/app"
install -m 0644 "$SRC/requirements.txt" "$APP/requirements.txt"
install -m 0644 "$SRC/VERSION" "$APP/VERSION"
"$APP/.venv/bin/pip" install -r "$APP/requirements.txt"
install -m 0644 "$SRC/systemd/dragon-vps-manager.service" /etc/systemd/system/dragon-vps-manager.service
install -m 0644 "$SRC/nginx/dragon-vps-manager.conf" /etc/nginx/sites-available/dragon-vps-manager
install -m 0755 "$SRC/scripts/update.sh" /usr/local/sbin/dragon-update
install -m 0755 "$SRC/scripts/backup.sh" /usr/local/sbin/dragon-backup
install -m 0755 "$SRC/scripts/uninstall.sh" /usr/local/sbin/dragon-uninstall
systemctl daemon-reload
nginx -t
systemctl restart dragon-vps-manager
systemctl reload nginx
curl -fsS http://127.0.0.1:8787/healthz >/dev/null
printf 'Update complete. Installed version: '
cat "$APP/VERSION"

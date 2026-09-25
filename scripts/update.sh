#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root."; exit 1; }

REPO="mahanneo/Makia-VPS-Manager"
REF="${MAKIA_REF:-${DRAGON_REF:-main}}"
APP=/opt/makia-vps-manager
OLD_APP=/opt/dragon-vps-manager-ng
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [[ ! -d "$APP" && -d "$OLD_APP" ]]; then
  echo "Legacy installation detected. Run the latest installer once to migrate to /opt/makia-vps-manager."
  exit 2
fi
[[ -d "$APP" ]] || { echo "Makia VPS Manager is not installed."; exit 1; }
install -d -m 0700 /var/backups/makia-vps-manager

BACKUP="$(/usr/local/sbin/makia-backup)"
echo "Backup created: $BACKUP"

curl -fL --retry 3 "https://github.com/${REPO}/archive/refs/heads/${REF}.tar.gz" -o "$TMP/source.tar.gz"
tar -xzf "$TMP/source.tar.gz" -C "$TMP"
SRC="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d -name 'Makia-VPS-Manager-*' | head -n1)"
[[ -n "$SRC" ]] || { echo "Unable to locate extracted source."; exit 1; }

systemctl stop makia-vps-manager
rm -rf "$APP/app"
cp -a "$SRC/app" "$APP/app"
install -m 0644 "$SRC/requirements.txt" "$APP/requirements.txt"
install -m 0644 "$SRC/VERSION" "$APP/VERSION"
"$APP/.venv/bin/pip" install -r "$APP/requirements.txt"

# Keep the weak-PIN mitigation baseline consistent on upgraded installs.
if ! command -v fail2ban-client >/dev/null 2>&1; then
  apt-get update
  apt-get install -y fail2ban
fi
install -d -m 0755 /etc/fail2ban/jail.d
cat >/etc/fail2ban/jail.d/makia-sshd.local <<'EOF'
[sshd]
enabled = true
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
EOF

install -m 0644 "$SRC/systemd/makia-vps-manager.service" /etc/systemd/system/makia-vps-manager.service
install -m 0644 "$SRC/systemd/makia-policy-enforcer.service" /etc/systemd/system/makia-policy-enforcer.service
install -m 0644 "$SRC/systemd/makia-metrics-sampler.service" /etc/systemd/system/makia-metrics-sampler.service
install -m 0644 "$SRC/nginx/makia-vps-manager.conf" /etc/nginx/sites-available/makia-vps-manager
ln -sfn /etc/nginx/sites-available/makia-vps-manager /etc/nginx/sites-enabled/makia-vps-manager
install -m 0755 "$SRC/scripts/update.sh" /usr/local/sbin/makia-update
install -m 0755 "$SRC/scripts/backup.sh" /usr/local/sbin/makia-backup
install -m 0755 "$SRC/scripts/uninstall.sh" /usr/local/sbin/makia-uninstall

systemctl daemon-reload
nginx -t
systemctl restart makia-vps-manager
systemctl enable --now makia-policy-enforcer
systemctl restart makia-policy-enforcer
systemctl enable --now makia-metrics-sampler
systemctl restart makia-metrics-sampler
systemctl enable --now fail2ban
systemctl restart fail2ban
systemctl reload nginx

for _ in {1..15}; do
  if curl -fsS http://127.0.0.1:8787/healthz >/dev/null; then
    printf 'Update complete. Installed version: '
    cat "$APP/VERSION"
    exit 0
  fi
  sleep 1
done

echo "Health check failed after update."
echo "Backup is available at: $BACKUP"
exit 3

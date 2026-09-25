#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/install.sh"
  exit 1
fi

if [[ ! -r /etc/os-release ]]; then
  echo "Unsupported system: /etc/os-release not found"
  exit 1
fi

# shellcheck disable=SC1091
source /etc/os-release
if [[ "${ID:-}" != "ubuntu" ]]; then
  echo "Unsupported OS: ${ID:-unknown}. Supported: Ubuntu 22.04/24.04."
  exit 1
fi
case "${VERSION_ID:-}" in
  22.04|24.04) ;;
  *) echo "Unsupported Ubuntu version: ${VERSION_ID:-unknown}. Supported: 22.04/24.04."; exit 1 ;;
esac

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP=/opt/dragon-vps-manager-ng
DATA="$APP/data"
ADMIN_PASSWORD="${DRAGON_INITIAL_ADMIN_PASSWORD:-}"
if [[ -z "$ADMIN_PASSWORD" ]]; then
  ADMIN_PASSWORD="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(24))
PY
)"
fi
if [[ ${#ADMIN_PASSWORD} -lt 16 ]]; then
  echo "DRAGON_INITIAL_ADMIN_PASSWORD must be at least 16 characters."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-venv python3-pip nginx curl ca-certificates

install -d -m 0750 "$APP" "$DATA"
cp -a "$SOURCE_DIR/app" "$SOURCE_DIR/requirements.txt" "$SOURCE_DIR/VERSION" "$APP/"
python3 -m venv "$APP/.venv"
"$APP/.venv/bin/pip" install --upgrade pip
"$APP/.venv/bin/pip" install -r "$APP/requirements.txt"

(
  cd "$APP"
  DRAGON_INITIAL_ADMIN_PASSWORD="$ADMIN_PASSWORD"   DRAGON_DATA_DIR="$DATA"   "$APP/.venv/bin/python" -c 'from app.db import init_db; init_db()'
)

install -m 0644 "$SOURCE_DIR/systemd/dragon-vps-manager.service" /etc/systemd/system/dragon-vps-manager.service
install -m 0644 "$SOURCE_DIR/nginx/dragon-vps-manager.conf" /etc/nginx/sites-available/dragon-vps-manager
ln -sfn /etc/nginx/sites-available/dragon-vps-manager /etc/nginx/sites-enabled/dragon-vps-manager
rm -f /etc/nginx/sites-enabled/default

install -m 0755 "$SOURCE_DIR/scripts/update.sh" /usr/local/sbin/dragon-update
install -m 0755 "$SOURCE_DIR/scripts/backup.sh" /usr/local/sbin/dragon-backup
install -m 0755 "$SOURCE_DIR/scripts/uninstall.sh" /usr/local/sbin/dragon-uninstall

systemctl daemon-reload
systemctl enable --now dragon-vps-manager
nginx -t
systemctl enable --now nginx
systemctl reload nginx

SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
printf '
Dragon VPS Manager NG installed successfully.
'
printf 'Panel: http://%s/
' "${SERVER_IP:-SERVER_IP}"
printf 'Username: admin
'
printf 'Bootstrap password: %s
' "$ADMIN_PASSWORD"
printf '
IMPORTANT: sign in and change this password immediately.
'
printf 'This alpha build should be tested on a non-production VPS first.

'

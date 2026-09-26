#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "$EUID" -ne 0 ]]; then echo "Run as root."; exit 1; fi
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRIVATE_KEY=""
PUBLIC_URL=""
PASSWORD=""
INGEST_TOKEN=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --private-key) PRIVATE_KEY="$2"; shift 2;;
    --public-url) PUBLIC_URL="$2"; shift 2;;
    --password) PASSWORD="$2"; shift 2;;
    --ingest-token) INGEST_TOKEN="$2"; shift 2;;
    *) echo "Unknown option: $1"; exit 2;;
  esac
done
[[ -f "$PRIVATE_KEY" ]] || { echo "--private-key must point to the Ed25519 owner private key"; exit 2; }
[[ "$PUBLIC_URL" == https://* ]] || { echo "--public-url must be HTTPS"; exit 2; }
[[ "${#PASSWORD}" -ge 14 ]] || { echo "--password must be at least 14 characters"; exit 2; }
if [[ -z "$INGEST_TOKEN" ]]; then INGEST_TOKEN="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"; fi
TOTP_SECRET="$(python3 - <<'PY'
import base64,secrets
print(base64.b32encode(secrets.token_bytes(20)).decode().rstrip("="))
PY
)"

id makia-owner >/dev/null 2>&1 || useradd --system --home /var/lib/makia-owner-console --shell /usr/sbin/nologin makia-owner
install -d -m 0750 -o root -g makia-owner /etc/makia-owner-console
install -d -m 0700 -o makia-owner -g makia-owner /var/lib/makia-owner-console
rm -rf /opt/makia-owner-console
install -d -m 0755 /opt/makia-owner-console
cp -a "$SOURCE_DIR/owner_console" "$SOURCE_DIR/requirements.txt" /opt/makia-owner-console/
python3 -m venv /opt/makia-owner-console/.venv
/opt/makia-owner-console/.venv/bin/pip install --upgrade pip
/opt/makia-owner-console/.venv/bin/pip install -r /opt/makia-owner-console/requirements.txt
install -m 0640 -o root -g makia-owner "$PRIVATE_KEY" /etc/makia-owner-console/license-private-key.pem
HASH="$(OWNER_PASSWORD="$PASSWORD" PYTHONPATH=/opt/makia-owner-console /opt/makia-owner-console/.venv/bin/python - <<'PY'
import os
from owner_console.security import hash_password
print(hash_password(os.environ["OWNER_PASSWORD"]))
PY
)"
cat >/etc/makia-owner-console/owner.env <<EOF
MAKIA_OWNER_DATA_DIR=/var/lib/makia-owner-console
MAKIA_OWNER_PRIVATE_KEY_PATH=/etc/makia-owner-console/license-private-key.pem
MAKIA_OWNER_PUBLIC_URL=$PUBLIC_URL
MAKIA_OWNER_ADMIN_PASSWORD_HASH=$HASH
MAKIA_OWNER_TOTP_SECRET=$TOTP_SECRET
MAKIA_OWNER_INGEST_TOKEN=$INGEST_TOKEN
MAKIA_OWNER_LEASE_TTL=86400
MAKIA_OWNER_LEASE_GRACE=259200
EOF
chown root:makia-owner /etc/makia-owner-console/owner.env
chmod 0640 /etc/makia-owner-console/owner.env
install -m 0644 "$SOURCE_DIR/systemd/makia-owner-console.service" /etc/systemd/system/makia-owner-console.service
systemctl daemon-reload
systemctl enable --now makia-owner-console
echo "Owner Control Center installed on http://127.0.0.1:8790"
echo "Public URL: $PUBLIC_URL"
echo "Client ticket ingest token (store securely): $INGEST_TOKEN"
echo "Owner TOTP secret (add to your authenticator now): $TOTP_SECRET"
echo "TOTP URI: otpauth://totp/Makia%20Owner?secret=$TOTP_SECRET&issuer=Makia"
echo "Configure Nginx/HTTPS before connecting customer panels."

#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root."; exit 1; }

REPO="mahanneo/Makia-VPS-Manager"
REF="${MAKIA_REF:-${DRAGON_REF:-main}}"
APP=/opt/makia-vps-manager
OLD_APP=/opt/dragon-vps-manager-ng
TMP="$(mktemp -d)"
ROLLBACK_ARMED=0
RELEASE_BACKUP=""

on_exit(){
  local rc=$?
  trap - EXIT
  if [[ "$rc" -ne 0 && "$ROLLBACK_ARMED" -eq 1 && -n "$RELEASE_BACKUP" && -f "$RELEASE_BACKUP" ]]; then
    echo
    echo "Update failed. Restoring previous Makia runtime..."
    set +e
    systemctl stop makia-vps-manager 2>/dev/null
    rm -rf "$APP/app"
    tar -xzf "$RELEASE_BACKUP" -C /
    if [[ -f "$APP/requirements.txt" && -x "$APP/.venv/bin/pip" ]]; then
      "$APP/.venv/bin/pip" install -r "$APP/requirements.txt" >/dev/null 2>&1
    fi
    systemctl daemon-reload
    nginx -t >/dev/null 2>&1 && systemctl reload nginx
    systemctl restart makia-vps-manager
    systemctl restart makia-policy-enforcer 2>/dev/null
    systemctl restart makia-metrics-sampler 2>/dev/null
    systemctl restart makia-protocol-traffic 2>/dev/null
    restored=0
    for _ in {1..12}; do
      if curl -fsS --max-time 3 http://127.0.0.1:8787/healthz >/dev/null 2>&1; then
        restored=1; break
      fi
      sleep 1
    done
    if [[ "$restored" -eq 1 ]]; then
      echo "Rollback successful. Previous backend is healthy again."
      echo "Runtime backup: $RELEASE_BACKUP"
    else
      echo "Rollback attempted, but backend is still unhealthy."
      echo "Run: sudo journalctl -u makia-vps-manager -n 120 --no-pager"
    fi
    set -e
  fi
  rm -rf "$TMP"
  exit "$rc"
}
trap on_exit EXIT

if [[ ! -d "$APP" && -d "$OLD_APP" ]]; then
  echo "Legacy installation detected. Run the latest installer once to migrate to /opt/makia-vps-manager."
  exit 2
fi
[[ -d "$APP" ]] || { echo "Makia VPS Manager is not installed."; exit 1; }
install -d -m 0700 /var/backups/makia-vps-manager

XRAY_WAS_PRESENT=0
XRAY_WAS_ACTIVE=0
if command -v xray >/dev/null 2>&1 && { [[ -f /usr/local/etc/xray/config.json ]] || [[ -f /etc/xray/config.json ]]; }; then
  XRAY_WAS_PRESENT=1
  systemctl is-active --quiet xray 2>/dev/null && XRAY_WAS_ACTIVE=1 || true
fi

STAMP_DATA="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="/var/backups/makia-vps-manager/makia-data-${STAMP_DATA}.tar.gz"
BACKUP_TMP="$(mktemp -d)"
mkdir -p "$BACKUP_TMP/data"

# Bootstrap-safe live backup: do not depend on an older installed makia-backup
# because the currently installed copy may itself be the reason the upgrade fails.
tar -C "$APP" -cf - \
  --exclude='data/makia.db' \
  --exclude='data/makia.db-wal' \
  --exclude='data/makia.db-shm' \
  data | tar -C "$BACKUP_TMP" -xf -

if [[ -f "$APP/data/makia.db" ]]; then
  SRC_DB="$APP/data/makia.db" DST_DB="$BACKUP_TMP/data/makia.db" python3 - <<'PY'
import os, sqlite3
src=os.environ["SRC_DB"]
dst=os.environ["DST_DB"]
source=sqlite3.connect(f"file:{src}?mode=ro", uri=True)
target=sqlite3.connect(dst)
try:
    source.backup(target)
    target.commit()
finally:
    target.close()
    source.close()
PY
  chmod 0600 "$BACKUP_TMP/data/makia.db"
fi

tar -C "$BACKUP_TMP" -czf "$BACKUP" data
chmod 0600 "$BACKUP"
rm -rf "$BACKUP_TMP"
echo "Data backup created: $BACKUP"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RELEASE_BACKUP="/var/backups/makia-vps-manager/makia-runtime-${STAMP}.tar.gz"
SNAPSHOT=("opt/makia-vps-manager/app" "opt/makia-vps-manager/requirements.txt" "opt/makia-vps-manager/VERSION")
for item in \
  "etc/systemd/system/makia-vps-manager.service" \
  "etc/systemd/system/makia-policy-enforcer.service" \
  "etc/systemd/system/makia-metrics-sampler.service" \
  "etc/systemd/system/makia-protocol-traffic.service" \
  "etc/nginx/sites-available/makia-vps-manager"; do
  [[ -e "/$item" ]] && SNAPSHOT+=("$item")
done
tar -C / -czf "$RELEASE_BACKUP" "${SNAPSHOT[@]}"
chmod 0600 "$RELEASE_BACKUP"
echo "Runtime rollback point: $RELEASE_BACKUP"

curl -fL --retry 3 "https://github.com/${REPO}/archive/refs/heads/${REF}.tar.gz" -o "$TMP/source.tar.gz"
tar -xzf "$TMP/source.tar.gz" -C "$TMP"
SRC="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d -name 'Makia-VPS-Manager-*' | head -n1)"
[[ -n "$SRC" ]] || { echo "Unable to locate extracted source."; exit 1; }

ROLLBACK_ARMED=1
systemctl stop makia-vps-manager
rm -rf "$APP/app"
cp -a "$SRC/app" "$APP/app"
install -m 0644 "$SRC/requirements.txt" "$APP/requirements.txt"
install -m 0644 "$SRC/VERSION" "$APP/VERSION"
"$APP/.venv/bin/pip" install -r "$APP/requirements.txt"

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
install -m 0644 "$SRC/systemd/makia-protocol-traffic.service" /etc/systemd/system/makia-protocol-traffic.service
if [[ ! -f /etc/nginx/sites-available/makia-vps-manager ]]; then
  install -m 0644 "$SRC/nginx/makia-vps-manager.conf" /etc/nginx/sites-available/makia-vps-manager
else
  echo "Preserving active Makia Nginx/Certbot configuration."
fi
ln -sfn /etc/nginx/sites-available/makia-vps-manager /etc/nginx/sites-enabled/makia-vps-manager
install -m 0755 "$SRC/scripts/update.sh" /usr/local/sbin/makia-update
install -m 0755 "$SRC/scripts/backup.sh" /usr/local/sbin/makia-backup
install -m 0755 "$SRC/scripts/uninstall.sh" /usr/local/sbin/makia-uninstall
install -m 0755 "$SRC/scripts/doctor.sh" /usr/local/sbin/makia-doctor
install -m 0755 "$SRC/scripts/uat-smoke.sh" /usr/local/sbin/makia-uat-smoke
install -m 0755 "$SRC/scripts/restore-portable.py" /usr/local/sbin/makia-restore-portable
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
install -m 0755 "$SRC/scripts/xray-cert-sync.sh" /etc/letsencrypt/renewal-hooks/deploy/makia-xray-sync
install -m 0755 "$SRC/scripts/reset-admin.sh" /usr/local/sbin/makia-reset-admin
install -m 0755 "$SRC/upgrade.sh" /usr/local/sbin/makia-upgrade

systemctl daemon-reload

# Repair the historical root-only Xray config/TLS permission mismatch before
# the post-update UAT gate. This preserves credentials and rolls back the
# Xray config internally if the repair itself cannot validate.
if command -v xray >/dev/null 2>&1 && { [[ -f /usr/local/etc/xray/config.json ]] || [[ -f /etc/xray/config.json ]]; }; then
  echo "Checking Xray runtime permissions as the real systemd user..."
  if ! ( cd "$APP" && MAKIA_DATA_DIR="$APP/data" "$APP/.venv/bin/python" - <<'PY'
from app import protocol_ops
d=protocol_ops.xray_diagnostics()
print("Xray:", d.get("version") or "unknown", "user="+str(d.get("service_user") or "root"))
if not d.get("service_validation") or not d.get("service_active"):
    result=protocol_ops.repair_xray_runtime()
    d=result["diagnostics"]
if not d.get("service_validation") or not d.get("service_active"):
    raise SystemExit("Xray runtime remains unhealthy after repair")
print("Xray runtime validation PASS")
PY
  ); then
    if [[ "$XRAY_WAS_ACTIVE" -eq 1 ]]; then
      echo "Xray was healthy before this update but is unhealthy now; updater will roll back."
      exit 5
    fi
    echo "WARNING: Xray was already unhealthy before the update and automatic repair could not fix it."
    echo "The panel update will continue so the new Diagnose/Repair UI is available."
  fi
fi

nginx -t
systemctl restart makia-vps-manager
systemctl enable --now makia-policy-enforcer
systemctl restart makia-policy-enforcer
systemctl enable --now makia-metrics-sampler
systemctl enable --now makia-protocol-traffic
systemctl restart makia-metrics-sampler
systemctl restart makia-protocol-traffic
systemctl enable --now fail2ban
systemctl restart fail2ban
systemctl reload nginx

healthy=0
for _ in {1..20}; do
  if curl -fsS --max-time 3 http://127.0.0.1:8787/healthz >/dev/null; then
    healthy=1; break
  fi
  sleep 1
done
if [[ "$healthy" -ne 1 ]]; then
  echo "Health check failed after update."
  echo "The updater will restore the previous runtime automatically."
  exit 3
fi

echo
echo "Running post-update Makia host smoke gate..."
UAT_ENV=()
if [[ "$XRAY_WAS_PRESENT" -eq 1 && "$XRAY_WAS_ACTIVE" -eq 0 ]] && ! systemctl is-active --quiet xray 2>/dev/null; then
  UAT_ENV=(env MAKIA_ALLOW_PREEXISTING_XRAY_FAILURE=1)
fi
if ! "${UAT_ENV[@]}" /usr/local/sbin/makia-uat-smoke; then
  echo "Post-update host smoke failed."
  echo "The updater will restore the previous runtime automatically."
  exit 4
fi

ROLLBACK_ARMED=0
printf 'Update complete. Installed version: '
cat "$APP/VERSION"
echo
/usr/local/sbin/makia-doctor || true

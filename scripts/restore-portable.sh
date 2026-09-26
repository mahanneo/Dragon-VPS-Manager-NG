#!/usr/bin/env bash
set -Eeuo pipefail

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root."; exit 1; }

APP=/opt/makia-vps-manager
BUNDLE="${1:-}"
MODE="${2:-}"
[[ -n "$BUNDLE" && -f "$BUNDLE" ]] || {
  echo "Usage: sudo makia-restore /path/to/makia-portable-*.zip [--apply]"
  exit 2
}
[[ -x "$APP/.venv/bin/python" ]] || {
  echo "Makia must be installed on the destination VPS before restore."
  exit 2
}

PASSWORD="${MAKIA_RESTORE_PASSWORD:-}"
if [[ -z "$PASSWORD" ]]; then
  read -r -s -p "Portable backup password: " PASSWORD
  echo
fi
[[ ${#PASSWORD} -ge 8 ]] || { echo "Password must be at least 8 characters."; exit 2; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/stage"

BUNDLE="$BUNDLE" PASSWORD="$PASSWORD" OUT="$TMP" "$APP/.venv/bin/python" - <<'PY'
import io, json, os, tarfile
from pathlib import Path
import pyzipper

bundle=Path(os.environ["BUNDLE"])
password=os.environ["PASSWORD"].encode("utf-8")
out=Path(os.environ["OUT"])
with pyzipper.AESZipFile(bundle,"r") as zf:
    zf.setpassword(password)
    names=set(zf.namelist())
    required={"manifest.json","makia-portable.tar.gz"}
    if not required.issubset(names):
        raise SystemExit("portable bundle is missing required files")
    manifest=json.loads(zf.read("manifest.json").decode("utf-8"))
    if manifest.get("format")!="makia-portable-v1":
        raise SystemExit("unsupported portable backup format")
    payload=zf.read("makia-portable.tar.gz")

(out/"manifest.json").write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
with tarfile.open(fileobj=io.BytesIO(payload),mode="r:gz") as tf:
    members=tf.getmembers()
    for member in members:
        p=Path(member.name)
        if member.name.startswith("/") or ".." in p.parts:
            raise SystemExit("unsafe path in portable archive")
        if member.issym() or member.islnk():
            target=Path(member.linkname)
            if member.linkname.startswith("/") or ".." in target.parts:
                raise SystemExit("unsafe link in portable archive")
    tf.extractall(out/"stage",filter="data")
print("Portable bundle verification: PASS")
PY

echo
cat "$TMP/manifest.json"
echo

if [[ "$MODE" != "--apply" ]]; then
  echo
  echo "Validation only. Re-run with --apply to restore this bundle."
  exit 0
fi

[[ -d "$TMP/stage/data" ]] || {
  echo "Portable bundle does not contain Makia data."
  exit 3
}

install -d -m 0700 /var/backups/makia-vps-manager
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
PRE="/var/backups/makia-vps-manager/pre-portable-restore-${STAMP}.tar.gz"
SNAPSHOT=()
for item in   opt/makia-vps-manager/data   etc/wireguard   usr/local/etc/xray/config.json   etc/xray/config.json   etc/openvpn   etc/nginx/sites-available/makia-vps-manager   etc/letsencrypt   etc/fail2ban/jail.d/makia-sshd.local; do
  [[ -e "/$item" ]] && SNAPSHOT+=("$item")
done
if [[ ${#SNAPSHOT[@]} -gt 0 ]]; then
  tar -C / -czf "$PRE" "${SNAPSHOT[@]}"
  chmod 0600 "$PRE"
  echo "Destination safety backup: $PRE"
fi

for svc in makia-vps-manager makia-policy-enforcer makia-metrics-sampler makia-protocol-traffic; do
  systemctl stop "$svc" 2>/dev/null || true
done
systemctl stop xray 2>/dev/null || true
systemctl stop wg-quick@wg0 2>/dev/null || true
for unit in $(systemctl list-unit-files 'openvpn-server@*.service' --no-legend 2>/dev/null | awk '{print $1}'); do
  systemctl stop "$unit" 2>/dev/null || true
done

rm -rf "$APP/data"
install -d -m 0750 "$APP/data"
cp -a "$TMP/stage/data/." "$APP/data/"
find "$APP/data" -type f -name '.secret' -exec chmod 0600 {} \; 2>/dev/null || true
find "$APP/data" -type f -name '*.db' -exec chmod 0600 {} \; 2>/dev/null || true

restore_tree(){
  local src="$1" dst="$2"
  [[ -e "$src" ]] || return 0
  rm -rf "$dst"
  install -d -m 0755 "$(dirname "$dst")"
  cp -a "$src" "$dst"
}

restore_file(){
  local src="$1" dst="$2"
  [[ -f "$src" ]] || return 0
  install -d -m 0755 "$(dirname "$dst")"
  cp -a "$src" "$dst"
}

restore_tree "$TMP/stage/host/etc/wireguard" /etc/wireguard
restore_file "$TMP/stage/host/usr/local/etc/xray/config.json" /usr/local/etc/xray/config.json
restore_file "$TMP/stage/host/etc/xray/config.json" /etc/xray/config.json
restore_tree "$TMP/stage/host/etc/openvpn" /etc/openvpn
restore_file "$TMP/stage/host/etc/nginx/sites-available/makia-vps-manager" /etc/nginx/sites-available/makia-vps-manager
restore_tree "$TMP/stage/host/etc/letsencrypt" /etc/letsencrypt
restore_file "$TMP/stage/host/etc/fail2ban/jail.d/makia-sshd.local" /etc/fail2ban/jail.d/makia-sshd.local

[[ -d /etc/wireguard ]] && chmod 0700 /etc/wireguard || true
[[ -d /etc/letsencrypt ]] && chmod 0700 /etc/letsencrypt || true

(
  cd "$APP"
  MAKIA_DATA_DIR="$APP/data" "$APP/.venv/bin/python" - <<'PY'
import re
from pathlib import Path
from app.db import init_db, all_profiles, list_access_artifacts
from app import access_ops, system_ops

init_db()
profiles=all_profiles()
artifacts={a["external_key"]:a for a in list_access_artifacts() if a.get("kind")=="ssh"}
restored=0
skipped=[]
for username,profile in profiles.items():
    password=""
    artifact=artifacts.get(username)
    if artifact:
        try:
            payload=access_ops.open_payload(artifact["payload_enc"])
            credentials=(payload.get("files") or {}).get("credentials.txt",b"")
            if isinstance(credentials,bytes):
                credentials=credentials.decode("utf-8","replace")
            match=re.search(r"(?m)^Password:\s*(.+)$",str(credentials))
            password=match.group(1).strip() if match else ""
        except Exception:
            password=""
    exists=False
    try:
        import pwd
        pwd.getpwnam(username)
        exists=True
    except KeyError:
        pass
    expire=profile.get("expire_date") or None
    try:
        if exists:
            system_ops.update_ssh_user(username,password=password or None,expire=expire,clear_expire=not bool(expire))
        elif password:
            system_ops.create_ssh_user(username,password,expire)
        else:
            skipped.append(username)
            continue
        system_ops.lock_user(username,not bool(profile.get("enabled",1)))
        restored+=1
    except Exception as exc:
        skipped.append(f"{username}: {str(exc)[:100]}")
print(f"SSH users restored/updated: {restored}")
if skipped:
    print("SSH users requiring manual credential reset:", ", ".join(skipped[:20]))
PY
)

if command -v xray >/dev/null 2>&1; then
  XRAY_CONFIG=""
  for candidate in /usr/local/etc/xray/config.json /etc/xray/config.json; do
    [[ -f "$candidate" ]] && { XRAY_CONFIG="$candidate"; break; }
  done
  if [[ -n "$XRAY_CONFIG" ]]; then
    xray run -test -format=json -config "$XRAY_CONFIG"
    systemctl enable --now xray
  fi
fi

if command -v wg >/dev/null 2>&1 && [[ -f /etc/wireguard/wg0.conf ]]; then
  systemctl enable --now wg-quick@wg0
fi

if command -v openvpn >/dev/null 2>&1 && [[ -d /etc/openvpn/server ]]; then
  for cfg in /etc/openvpn/server/*.conf; do
    [[ -f "$cfg" ]] || continue
    name="$(basename "$cfg" .conf)"
    systemctl enable --now "openvpn-server@${name}" || true
  done
fi

systemctl daemon-reload
if nginx -t; then
  systemctl enable --now nginx
  systemctl reload nginx
else
  echo "Nginx validation failed after restore. Safety backup: $PRE"
  exit 4
fi

systemctl enable --now makia-vps-manager
systemctl enable --now makia-policy-enforcer
systemctl enable --now makia-metrics-sampler
systemctl enable --now makia-protocol-traffic
systemctl restart fail2ban 2>/dev/null || true

healthy=0
for _ in {1..20}; do
  if curl -fsS --max-time 3 http://127.0.0.1:8787/healthz >/dev/null 2>&1; then
    healthy=1; break
  fi
  sleep 1
done
[[ "$healthy" -eq 1 ]] || {
  echo "Backend health check failed after restore. Safety backup: $PRE"
  exit 5
}

if command -v makia-uat-smoke >/dev/null 2>&1; then
  makia-uat-smoke
fi

echo
echo "Portable restore applied successfully."
echo "Now point the SAME panel/client DNS A/AAAA record to this VPS."
echo "Clients created with the domain and preserved keys/credentials should reconnect without reissuing configs."
echo "Existing live sessions will reconnect; DNS propagation and network state can cause a temporary interruption."

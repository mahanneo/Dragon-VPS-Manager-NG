#!/usr/bin/env bash
set -Eeuo pipefail

APP=/opt/makia-vps-manager
FAIL=0

ok(){ printf '✓ %s\n' "$1"; }
bad(){ printf '✗ %s\n' "$1"; FAIL=1; }

[[ -d "$APP" ]] || { bad "Makia runtime missing at $APP"; exit 1; }

printf '\nMakia v0.13 host smoke\n'
printf '%s\n' '---------------------'

VERSION="$(cat "$APP/VERSION" 2>/dev/null || true)"
[[ -n "$VERSION" ]] && ok "Version: $VERSION" || bad "VERSION missing"

if curl -fsS --max-time 4 http://127.0.0.1:8787/healthz >/tmp/makia-health.json; then
  ok "Backend health endpoint"
else
  bad "Backend health endpoint"
fi

if nginx -t >/dev/null 2>&1; then ok "Nginx config"; else bad "Nginx config"; fi

for svc in makia-vps-manager makia-policy-enforcer makia-metrics-sampler makia-protocol-traffic nginx fail2ban; do
  if systemctl is-active --quiet "$svc"; then ok "Service $svc"; else bad "Service $svc"; fi
done

if ( cd "$APP" && "$APP/.venv/bin/python" - <<'PY'
from app import access_ops
from app.db import connect
from app.config import SECRET_PATH
import os, stat

with connect() as con:
    result=con.execute("PRAGMA integrity_check").fetchone()[0]
assert str(result).lower()=="ok", result

assert SECRET_PATH.exists(), "server secret missing"
mode=stat.S_IMODE(os.stat(SECRET_PATH).st_mode)
assert mode==0o600, oct(mode)

blob=access_ops.protected_zip({"probe.txt":b"makia-self-test"},"582941")
result=access_ops.verify_protected_zip(blob,"582941","probe.txt")
assert result["ok"]
assert result["sample_size"]==15
print("storage/crypto PASS")
PY
)
then
  ok "SQLite integrity + secret permission + AES ZIP"
else
  bad "SQLite integrity / crypto smoke"
fi

if ( cd "$APP" && "$APP/.venv/bin/python" -c 'import app.main; print(app.main.APP_NAME, app.main.VERSION)' ) >/tmp/makia-import.txt; then
  ok "Application import"
else
  bad "Application import"
fi

if command -v xray >/dev/null 2>&1; then
  XRAY_CONFIG=""
  for candidate in /usr/local/etc/xray/config.json /etc/xray/config.json; do
    if [[ -f "$candidate" ]]; then XRAY_CONFIG="$candidate"; break; fi
  done
  if [[ -n "$XRAY_CONFIG" ]]; then
    if xray run -test -format=json -config "$XRAY_CONFIG" >/tmp/makia-xray-test.log 2>&1; then
      ok "Xray active config syntax (root)"
    else
      bad "Xray active config syntax (root)"
      sed -n '1,12p' /tmp/makia-xray-test.log || true
    fi
    XRAY_USER="$(systemctl show xray -p User --value 2>/dev/null || true)"
    XRAY_USER="${XRAY_USER:-root}"
    if [[ "$XRAY_USER" == "root" ]]; then
      XRAY_USER_TEST=( xray run -test -format=json -config "$XRAY_CONFIG" )
    else
      XRAY_USER_TEST=( runuser -u "$XRAY_USER" -- xray run -test -format=json -config "$XRAY_CONFIG" )
    fi
    if "${XRAY_USER_TEST[@]}" >/tmp/makia-xray-user-test.log 2>&1; then
      ok "Xray config readable by systemd user ($XRAY_USER)"
    else
      bad "Xray config unreadable/invalid for systemd user ($XRAY_USER)"
      sed -n '1,12p' /tmp/makia-xray-user-test.log || true
    fi
    if systemctl is-active --quiet xray; then
      ok "Xray runtime active"
    else
      bad "Xray runtime inactive"
      journalctl -u xray -n 12 --no-pager || true
    fi
  fi
fi

if [[ -x /etc/letsencrypt/renewal-hooks/deploy/makia-xray-sync ]]; then
  ok "Xray Certbot deploy hook"
else
  bad "Xray Certbot deploy hook missing"
fi

if [[ -f /etc/wireguard/wg0.conf ]]; then
  if command -v wg >/dev/null 2>&1 && wg show wg0 >/tmp/makia-wg-show.txt 2>&1; then
    ok "WireGuard wg0 runtime"
  else
    bad "WireGuard wg0 runtime"
  fi
fi

if command -v makia-restore-portable >/dev/null 2>&1; then
  ok "Portable restore command"
else
  bad "Portable restore command missing"
fi

if command -v makia-doctor >/dev/null 2>&1; then
  makia-doctor || true
else
  bad "makia-doctor command missing"
fi

printf '\n'
if [[ "$FAIL" -eq 0 ]]; then
  printf 'HOST SMOKE: PASS\n'
else
  printf 'HOST SMOKE: FAIL\n'
fi
exit "$FAIL"

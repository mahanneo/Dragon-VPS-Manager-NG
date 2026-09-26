#!/usr/bin/env bash
set -Eeuo pipefail

APP=/opt/makia-vps-manager
FAIL=0

ok(){ printf '✓ %s\n' "$1"; }
bad(){ printf '✗ %s\n' "$1"; FAIL=1; }

[[ -d "$APP" ]] || { bad "Makia runtime missing at $APP"; exit 1; }

printf '\nMakia v0.11 host smoke\n'
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

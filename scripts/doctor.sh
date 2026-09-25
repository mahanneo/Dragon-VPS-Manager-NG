#!/usr/bin/env bash
set -uo pipefail

PASS=0
WARN=0
FAIL=0

ok(){ PASS=$((PASS+1)); printf '✓ %-30s %s\n' "$1" "${2:-OK}"; }
warn(){ WARN=$((WARN+1)); printf '! %-30s %s\n' "$1" "$2"; }
fail(){ FAIL=$((FAIL+1)); printf '✗ %-30s %s\n' "$1" "$2"; }

check_service(){
  local service="$1" label="$2" required="${3:-yes}"
  if systemctl is-active --quiet "$service" 2>/dev/null; then
    ok "$label" "active"
  elif [[ "$required" == "yes" ]]; then
    fail "$label" "$(systemctl is-active "$service" 2>/dev/null || true)"
  else
    warn "$label" "$(systemctl is-active "$service" 2>/dev/null || echo not-installed)"
  fi
}

printf '\nMakia VPS Manager Doctor\n'
printf '========================\n'
if [[ -r /opt/makia-vps-manager/VERSION ]]; then
  ok "Version" "$(cat /opt/makia-vps-manager/VERSION)"
else
  fail "Version" "/opt/makia-vps-manager/VERSION missing"
fi

check_service makia-vps-manager "Makia backend"
check_service nginx "Nginx"
check_service makia-policy-enforcer "SSH policy enforcer"
check_service makia-metrics-sampler "Metrics sampler"
check_service makia-protocol-traffic "Protocol traffic collector"
check_service fail2ban "Fail2ban"

TMP_HEALTH="$(mktemp)"
if curl -fsS --max-time 5 http://127.0.0.1:8787/healthz >"$TMP_HEALTH" 2>/dev/null; then
  ok "Backend health" "$(cat "$TMP_HEALTH")"
else
  fail "Backend health" "http://127.0.0.1:8787/healthz failed"
fi
rm -f "$TMP_HEALTH"

TMP_NGINX="$(mktemp)"
if nginx -t >"$TMP_NGINX" 2>&1; then
  ok "Nginx config" "valid"
else
  fail "Nginx config" "$(tail -n 2 "$TMP_NGINX" | tr '\n' ' ')"
fi
rm -f "$TMP_NGINX"

DB=/opt/makia-vps-manager/data/makia.db
if [[ -f "$DB" ]]; then
  PERM="$(stat -c '%a' "$DB" 2>/dev/null || echo unknown)"
  if [[ "$PERM" == "600" ]]; then ok "Database permissions" "0600"; else warn "Database permissions" "$PERM (expected 600 after next DB access)"; fi
else
  warn "Database" "not found yet"
fi

XRAY="$(command -v xray 2>/dev/null || true)"
if [[ -n "$XRAY" ]]; then
  CONF=""
  [[ -f /usr/local/etc/xray/config.json ]] && CONF=/usr/local/etc/xray/config.json
  [[ -z "$CONF" && -f /etc/xray/config.json ]] && CONF=/etc/xray/config.json
  if [[ -n "$CONF" ]]; then
    TMP_XRAY="$(mktemp)"
    if "$XRAY" run -test -config "$CONF" >"$TMP_XRAY" 2>&1; then
      ok "Xray config" "valid"
    else
      fail "Xray config" "$(tail -n 2 "$TMP_XRAY" | tr '\n' ' ')"
    fi
    rm -f "$TMP_XRAY"
    check_service xray "Xray service" no
  else
    warn "Xray" "binary installed, config not found"
  fi
else
  warn "Xray" "not installed (optional)"
fi

if command -v wg >/dev/null 2>&1; then
  if wg show >/dev/null 2>&1; then ok "WireGuard tooling" "ready"; else warn "WireGuard tooling" "installed but no readable interface"; fi
else
  warn "WireGuard" "not installed (optional)"
fi

if command -v openvpn >/dev/null 2>&1; then
  ok "OpenVPN tooling" "$(openvpn --version 2>/dev/null | head -n1)"
else
  warn "OpenVPN" "not installed (optional)"
fi

printf '\nSummary: %d PASS · %d WARN · %d FAIL\n\n' "$PASS" "$WARN" "$FAIL"
[[ "$FAIL" -eq 0 ]]

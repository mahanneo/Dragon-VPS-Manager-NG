#!/usr/bin/env bash
set -Eeuo pipefail

XRAY_BIN="$(command -v xray 2>/dev/null || true)"
[[ -n "$XRAY_BIN" ]] || exit 0

CONFIG=""
for candidate in /usr/local/etc/xray/config.json /etc/xray/config.json; do
  if [[ -f "$candidate" ]]; then CONFIG="$candidate"; break; fi
done
[[ -n "$CONFIG" ]] || exit 0

DOMAIN="${1:-${RENEWED_DOMAINS%% *}}"
LINEAGE="${RENEWED_LINEAGE:-}"
if [[ -z "$DOMAIN" || ! "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]]; then
  echo "Makia Xray TLS sync: no safe renewed domain supplied; nothing to do."
  exit 0
fi
if [[ -z "$LINEAGE" ]]; then LINEAGE="/etc/letsencrypt/live/$DOMAIN"; fi
[[ -f "$LINEAGE/fullchain.pem" && -f "$LINEAGE/privkey.pem" ]] || exit 0

TARGET="/usr/local/etc/xray/tls/$DOMAIN"
[[ -d "$TARGET" ]] || exit 0

XRAY_USER="$(systemctl show xray -p User --value 2>/dev/null || true)"
XRAY_USER="${XRAY_USER:-root}"
if ! id "$XRAY_USER" >/dev/null 2>&1; then
  echo "Makia Xray TLS sync: systemd user '$XRAY_USER' does not exist."
  exit 1
fi
XRAY_GROUP="$(id -gn "$XRAY_USER")"

install -d -m 0700 -o "$XRAY_USER" -g "$XRAY_GROUP" "$TARGET"
TMP_CERT="$TARGET/.fullchain.pem.makia.$$"
TMP_KEY="$TARGET/.privkey.pem.makia.$$"
trap 'rm -f "$TMP_CERT" "$TMP_KEY"' EXIT
install -m 0600 -o "$XRAY_USER" -g "$XRAY_GROUP" "$LINEAGE/fullchain.pem" "$TMP_CERT"
install -m 0600 -o "$XRAY_USER" -g "$XRAY_GROUP" "$LINEAGE/privkey.pem" "$TMP_KEY"
mv -f "$TMP_CERT" "$TARGET/fullchain.pem"
mv -f "$TMP_KEY" "$TARGET/privkey.pem"
chown "$XRAY_USER:$XRAY_GROUP" "$TARGET/fullchain.pem" "$TARGET/privkey.pem"
chmod 0600 "$TARGET/fullchain.pem" "$TARGET/privkey.pem"

if [[ "$XRAY_USER" == "root" ]]; then
  "$XRAY_BIN" run -test -format=json -config "$CONFIG"
else
  runuser -u "$XRAY_USER" -- "$XRAY_BIN" run -test -format=json -config "$CONFIG"
fi

if systemctl is-active --quiet xray; then
  systemctl restart xray
  systemctl is-active --quiet xray
fi

echo "Makia Xray TLS sync: $DOMAIN updated successfully."

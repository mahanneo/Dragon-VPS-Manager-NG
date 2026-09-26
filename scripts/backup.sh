#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root."; exit 1; }

APP=/opt/makia-vps-manager
DATA="$APP/data"
OUT_DIR=/var/backups/makia-vps-manager
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

install -d -m 0700 "$OUT_DIR"
[[ -d "$DATA" ]] || { echo "No Makia data directory found."; exit 1; }

mkdir -p "$TMP/data"

# Copy non-SQLite state first. Exclude live SQLite files because copying them
# while WAL/transactions change can produce an inconsistent archive.
tar -C "$APP" -cf - \
  --exclude='data/makia.db' \
  --exclude='data/makia.db-wal' \
  --exclude='data/makia.db-shm' \
  data | tar -C "$TMP" -xf -

if [[ -f "$DATA/makia.db" ]]; then
  SRC_DB="$DATA/makia.db" DST_DB="$TMP/data/makia.db" python3 - <<'PY'
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
  chmod 0600 "$TMP/data/makia.db"
fi

OUT="$OUT_DIR/makia-data-$STAMP.tar.gz"
tar -C "$TMP" -czf "$OUT" data
chmod 0600 "$OUT"
echo "$OUT"

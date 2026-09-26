import os
from pathlib import Path

DATA_DIR=Path(os.getenv("MAKIA_OWNER_DATA_DIR","/var/lib/makia-owner-console"))
DB_PATH=DATA_DIR/"owner.db"
SECRET_PATH=DATA_DIR/".session-secret"
PRIVATE_KEY_PATH=Path(os.getenv("MAKIA_OWNER_PRIVATE_KEY_PATH","/etc/makia-owner-console/license-private-key.pem"))
PUBLIC_URL=(os.getenv("MAKIA_OWNER_PUBLIC_URL") or "").strip().rstrip("/")
ADMIN_PASSWORD_HASH=(os.getenv("MAKIA_OWNER_ADMIN_PASSWORD_HASH") or "").strip()
TOTP_SECRET=(os.getenv("MAKIA_OWNER_TOTP_SECRET") or "").strip()
INGEST_TOKEN=(os.getenv("MAKIA_OWNER_INGEST_TOKEN") or "").strip()
COOKIE_NAME="makia_owner_session"
LEASE_TTL_SECONDS=max(3600,min(int(os.getenv("MAKIA_OWNER_LEASE_TTL","86400")),172800))
LEASE_GRACE_SECONDS=max(3600,min(int(os.getenv("MAKIA_OWNER_LEASE_GRACE","259200")),604800))

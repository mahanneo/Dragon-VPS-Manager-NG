#!/usr/bin/env bash
set -Eeuo pipefail

APP=/opt/makia-vps-manager
USERNAME="admin"
MODE="prompt"
DISABLE_2FA=0

usage(){
  cat <<'EOF'
Usage:
  sudo makia-reset-admin
  sudo makia-reset-admin --generate
  sudo makia-reset-admin --user USERNAME
  sudo makia-reset-admin --generate --disable-2fa

Options:
  --user USERNAME   Reset a specific administrator (default: admin)
  --generate        Generate a strong password and print it once
  --disable-2fa     Also disable TOTP 2FA for this administrator
  -h, --help        Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)
      [[ $# -ge 2 ]] || { echo "Missing value for --user"; exit 2; }
      USERNAME="$2"; shift 2 ;;
    --generate) MODE="generate"; shift ;;
    --disable-2fa) DISABLE_2FA=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1"; usage; exit 2 ;;
  esac
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root: sudo makia-reset-admin"; exit 1; }
[[ -x "$APP/.venv/bin/python" ]] || { echo "Makia Python environment not found under $APP/.venv"; exit 1; }
[[ -f "$APP/data/makia.db" ]] || { echo "Makia database not found: $APP/data/makia.db"; exit 1; }

PASSWORD=""
if [[ "$MODE" == "prompt" ]]; then
  read -rsp "New password for ${USERNAME}: " PASSWORD; echo
  read -rsp "Repeat password: " PASSWORD2; echo
  [[ "$PASSWORD" == "$PASSWORD2" ]] || { echo "Passwords do not match."; exit 2; }
  [[ ${#PASSWORD} -ge 12 ]] || { echo "Administrator password must be at least 12 characters."; exit 2; }
fi

export MAKIA_RESET_USERNAME="$USERNAME"
export MAKIA_RESET_MODE="$MODE"
export MAKIA_RESET_PASSWORD="$PASSWORD"
export MAKIA_RESET_DISABLE_2FA="$DISABLE_2FA"
export MAKIA_DATA_DIR="$APP/data"

RESULT="$(
  cd "$APP"
  "$APP/.venv/bin/python" - <<'PY'
import os, secrets, sqlite3
from app.config import DB_PATH
from app.security import hash_password

username=os.environ["MAKIA_RESET_USERNAME"]
mode=os.environ["MAKIA_RESET_MODE"]
password=os.environ.get("MAKIA_RESET_PASSWORD","")
disable_2fa=os.environ.get("MAKIA_RESET_DISABLE_2FA")=="1"

if mode=="generate":
    alphabet="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%"
    password="".join(secrets.choice(alphabet) for _ in range(20))

if len(password)<12:
    raise SystemExit("password must be at least 12 characters")

con=sqlite3.connect(DB_PATH)
con.row_factory=sqlite3.Row
row=con.execute("SELECT id,username FROM admins WHERE username=?",(username,)).fetchone()
if not row:
    names=[r["username"] for r in con.execute("SELECT username FROM admins ORDER BY id").fetchall()]
    raise SystemExit("administrator not found. Available: "+(", ".join(names) if names else "(none)"))

if disable_2fa:
    con.execute(
        "UPDATE admins SET password_hash=?,active=1,totp_secret=NULL,totp_enabled=0 WHERE username=?",
        (hash_password(password),username)
    )
else:
    con.execute(
        "UPDATE admins SET password_hash=?,active=1 WHERE username=?",
        (hash_password(password),username)
    )
con.execute("DELETE FROM login_rate_limits")
con.commit()
con.close()
print(password)
PY
)"

unset MAKIA_RESET_PASSWORD MAKIA_RESET_USERNAME MAKIA_RESET_MODE MAKIA_RESET_DISABLE_2FA

echo
echo "Administrator credentials reset successfully."
echo "Username: $USERNAME"
if [[ "$MODE" == "generate" ]]; then
  echo "New password: $RESULT"
  echo "IMPORTANT: save this password now. It will not be shown again."
else
  echo "Password: updated"
fi
if [[ "$DISABLE_2FA" -eq 1 ]]; then
  echo "2FA: disabled"
fi
echo "Login throttling state: cleared"

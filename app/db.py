import os
import sqlite3
from datetime import datetime, timezone
from .config import DB_PATH
from .security import hash_password

def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def _columns(con, table):
    return {r["name"] for r in con.execute(f"PRAGMA table_info({table})").fetchall()}

def _add_column(con, table, definition):
    name = definition.split()[0]
    if name not in _columns(con, table):
        con.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")

def init_db():
    with connect() as con:
        con.executescript('''
        CREATE TABLE IF NOT EXISTS admins (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          actor TEXT NOT NULL,
          action TEXT NOT NULL,
          target TEXT,
          detail TEXT,
          ip TEXT,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS account_profiles (
          username TEXT PRIMARY KEY,
          plan TEXT NOT NULL DEFAULT '',
          note TEXT NOT NULL DEFAULT '',
          expire_date TEXT,
          connection_limit INTEGER NOT NULL DEFAULT 1,
          quota_mb INTEGER NOT NULL DEFAULT 0,
          enabled INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        ''')
        # Migration-safe columns for future profile growth.
        _add_column(con, "account_profiles", "plan TEXT NOT NULL DEFAULT ''")
        _add_column(con, "account_profiles", "note TEXT NOT NULL DEFAULT ''")
        _add_column(con, "account_profiles", "expire_date TEXT")
        _add_column(con, "account_profiles", "connection_limit INTEGER NOT NULL DEFAULT 1")
        _add_column(con, "account_profiles", "quota_mb INTEGER NOT NULL DEFAULT 0")
        _add_column(con, "account_profiles", "enabled INTEGER NOT NULL DEFAULT 1")
        _add_column(con, "account_profiles", "created_at TEXT NOT NULL DEFAULT ''")
        _add_column(con, "account_profiles", "updated_at TEXT NOT NULL DEFAULT ''")

        if not con.execute("SELECT 1 FROM admins LIMIT 1").fetchone():
            initial_password = os.getenv("DRAGON_INITIAL_ADMIN_PASSWORD") or os.getenv("MAKIA_INITIAL_ADMIN_PASSWORD")
            if not initial_password or len(initial_password) < 16:
                raise RuntimeError(
                    "Empty database requires MAKIA_INITIAL_ADMIN_PASSWORD (minimum 16 characters). "
                    "Use the official installer to bootstrap securely."
                )
            con.execute(
                "INSERT INTO admins(username,password_hash,created_at) VALUES(?,?,?)",
                ("admin", hash_password(initial_password), now())
            )

def now():
    return datetime.now(timezone.utc).isoformat()

def audit(actor, action, target=None, detail=None, ip=None):
    with connect() as con:
        con.execute(
            "INSERT INTO audit_logs(actor,action,target,detail,ip,created_at) VALUES(?,?,?,?,?,?)",
            (actor, action, target, detail, ip, now())
        )

def upsert_profile(username, plan="", note="", expire_date=None, connection_limit=1, quota_mb=0, enabled=1):
    ts=now()
    with connect() as con:
        con.execute(
            """INSERT INTO account_profiles(username,plan,note,expire_date,connection_limit,quota_mb,enabled,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?)
               ON CONFLICT(username) DO UPDATE SET
                 plan=excluded.plan,note=excluded.note,expire_date=excluded.expire_date,
                 connection_limit=excluded.connection_limit,quota_mb=excluded.quota_mb,
                 enabled=excluded.enabled,updated_at=excluded.updated_at""",
            (username, plan or "", note or "", expire_date, max(1,int(connection_limit or 1)),
             max(0,int(quota_mb or 0)), 1 if enabled else 0, ts, ts)
        )

def get_profile(username):
    with connect() as con:
        row=con.execute("SELECT * FROM account_profiles WHERE username=?",(username,)).fetchone()
        return dict(row) if row else None

def all_profiles():
    with connect() as con:
        return {r["username"]:dict(r) for r in con.execute("SELECT * FROM account_profiles").fetchall()}

def delete_profile(username):
    with connect() as con:
        con.execute("DELETE FROM account_profiles WHERE username=?",(username,))

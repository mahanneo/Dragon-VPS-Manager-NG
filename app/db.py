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
        ''')
        if not con.execute("SELECT 1 FROM admins LIMIT 1").fetchone():
            initial_password = os.getenv("DRAGON_INITIAL_ADMIN_PASSWORD")
            if not initial_password or len(initial_password) < 16:
                raise RuntimeError(
                    "Empty database requires DRAGON_INITIAL_ADMIN_PASSWORD (minimum 16 characters). "
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

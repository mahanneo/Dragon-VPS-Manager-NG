import os
import sqlite3
import hashlib, secrets
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
        CREATE TABLE IF NOT EXISTS metrics_history (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts INTEGER NOT NULL,
          cpu REAL NOT NULL,
          memory REAL NOT NULL,
          disk REAL NOT NULL,
          load1 REAL NOT NULL,
          rx INTEGER NOT NULL,
          tx INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_metrics_history_ts ON metrics_history(ts);
        CREATE TABLE IF NOT EXISTS api_tokens (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          token_hash TEXT UNIQUE NOT NULL,
          token_last4 TEXT NOT NULL,
          scopes TEXT NOT NULL,
          active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL,
          last_used_at TEXT
        );
        CREATE TABLE IF NOT EXISTS nodes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          token_hash TEXT UNIQUE NOT NULL,
          token_last4 TEXT NOT NULL,
          active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL,
          last_seen_at TEXT,
          hostname TEXT,
          version TEXT,
          cpu REAL,
          memory REAL,
          disk REAL
        );
        CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen_at);
        CREATE TABLE IF NOT EXISTS protocol_clients (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          engine TEXT NOT NULL,
          protocol TEXT NOT NULL,
          inbound_tag TEXT NOT NULL,
          credential TEXT NOT NULL,
          share_link TEXT NOT NULL,
          quota_bytes INTEGER NOT NULL DEFAULT 0,
          expire_at INTEGER NOT NULL DEFAULT 0,
          ip_limit INTEGER NOT NULL DEFAULT 1,
          enabled INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          UNIQUE(engine,inbound_tag,name)
        );
        CREATE INDEX IF NOT EXISTS idx_protocol_clients_name ON protocol_clients(name);
        CREATE TABLE IF NOT EXISTS account_profiles (
          username TEXT PRIMARY KEY,
          plan TEXT NOT NULL DEFAULT '',
          note TEXT NOT NULL DEFAULT '',
          expire_date TEXT,
          connection_limit INTEGER NOT NULL DEFAULT 1,
          device_limit INTEGER NOT NULL DEFAULT 1,
          quota_mb INTEGER NOT NULL DEFAULT 0,
          renewal_days INTEGER NOT NULL DEFAULT 0,
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
        _add_column(con, "account_profiles", "device_limit INTEGER NOT NULL DEFAULT 1")
        _add_column(con, "account_profiles", "quota_mb INTEGER NOT NULL DEFAULT 0")
        _add_column(con, "account_profiles", "renewal_days INTEGER NOT NULL DEFAULT 0")
        _add_column(con, "account_profiles", "enabled INTEGER NOT NULL DEFAULT 1")
        _add_column(con, "account_profiles", "created_at TEXT NOT NULL DEFAULT ''")
        _add_column(con, "account_profiles", "updated_at TEXT NOT NULL DEFAULT ''")

        _add_column(con, "admins", "totp_secret TEXT")
        _add_column(con, "admins", "totp_enabled INTEGER NOT NULL DEFAULT 0")

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

def upsert_profile(username, plan="", note="", expire_date=None, connection_limit=1, quota_mb=0, enabled=1, device_limit=1, renewal_days=0):
    ts=now()
    with connect() as con:
        con.execute(
            """INSERT INTO account_profiles(username,plan,note,expire_date,connection_limit,device_limit,quota_mb,renewal_days,enabled,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(username) DO UPDATE SET
                 plan=excluded.plan,note=excluded.note,expire_date=excluded.expire_date,
                 connection_limit=excluded.connection_limit,device_limit=excluded.device_limit,
                 quota_mb=excluded.quota_mb,renewal_days=excluded.renewal_days,
                 enabled=excluded.enabled,updated_at=excluded.updated_at""",
            (username, plan or "", note or "", expire_date, max(1,int(connection_limit or 1)),
             max(1,int(device_limit or 1)), max(0,int(quota_mb or 0)), max(0,int(renewal_days or 0)),
             1 if enabled else 0, ts, ts)
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


def add_metric(ts,cpu,memory,disk,load1,rx,tx):
    with connect() as con:
        con.execute("INSERT INTO metrics_history(ts,cpu,memory,disk,load1,rx,tx) VALUES(?,?,?,?,?,?,?)",
                    (int(ts),float(cpu),float(memory),float(disk),float(load1),int(rx),int(tx)))
        # Keep 7 days at one-minute sampling with a small safety margin.
        con.execute("DELETE FROM metrics_history WHERE ts < ?",(int(ts)-8*86400,))

def metrics_since(since_ts,limit=2000):
    with connect() as con:
        rows=con.execute(
            "SELECT ts,cpu,memory,disk,load1,rx,tx FROM metrics_history WHERE ts>=? ORDER BY ts ASC LIMIT ?",
            (int(since_ts),max(1,min(int(limit),10000)))
        ).fetchall()
        return [dict(r) for r in rows]


def get_admin_2fa(username):
    with connect() as con:
        row=con.execute("SELECT username,totp_secret,totp_enabled FROM admins WHERE username=?",(username,)).fetchone()
        return dict(row) if row else None

def set_admin_totp_secret(username,secret):
    with connect() as con:
        con.execute("UPDATE admins SET totp_secret=?,totp_enabled=0 WHERE username=?",(secret,username))

def set_admin_totp_enabled(username,enabled):
    with connect() as con:
        con.execute("UPDATE admins SET totp_enabled=? WHERE username=?",(1 if enabled else 0,username))

def clear_admin_totp(username):
    with connect() as con:
        con.execute("UPDATE admins SET totp_secret=NULL,totp_enabled=0 WHERE username=?",(username,))


def _token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()

def create_api_token(name,scopes):
    token="mk_"+secrets.token_urlsafe(32)
    ts=now()
    scopes_text=",".join(sorted(set(scopes)))
    with connect() as con:
        cur=con.execute(
            "INSERT INTO api_tokens(name,token_hash,token_last4,scopes,active,created_at) VALUES(?,?,?,?,1,?)",
            (name,_token_hash(token),token[-4:],scopes_text,ts)
        )
        token_id=cur.lastrowid
    return {"id":token_id,"token":token,"name":name,"scopes":scopes_text.split(",") if scopes_text else []}

def list_api_tokens():
    with connect() as con:
        rows=con.execute("SELECT id,name,token_last4,scopes,active,created_at,last_used_at FROM api_tokens ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

def revoke_api_token(token_id):
    with connect() as con:
        con.execute("UPDATE api_tokens SET active=0 WHERE id=?",(int(token_id),))

def verify_api_token(token,required_scope=None):
    h=_token_hash(token)
    with connect() as con:
        row=con.execute("SELECT * FROM api_tokens WHERE token_hash=? AND active=1",(h,)).fetchone()
        if not row:
            return None
        scopes={s for s in (row["scopes"] or "").split(",") if s}
        if required_scope and required_scope not in scopes and "*" not in scopes:
            return None
        con.execute("UPDATE api_tokens SET last_used_at=? WHERE id=?",(now(),row["id"]))
        return {"id":row["id"],"name":row["name"],"scopes":sorted(scopes)}

def create_node(name):
    token="mn_"+secrets.token_urlsafe(32)
    ts=now()
    with connect() as con:
        cur=con.execute(
            "INSERT INTO nodes(name,token_hash,token_last4,active,created_at) VALUES(?,?,?,1,?)",
            (name,_token_hash(token),token[-4:],ts)
        )
        node_id=cur.lastrowid
    return {"id":node_id,"name":name,"token":token}

def list_nodes():
    with connect() as con:
        rows=con.execute("SELECT id,name,token_last4,active,created_at,last_seen_at,hostname,version,cpu,memory,disk FROM nodes ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

def revoke_node(node_id):
    with connect() as con:
        con.execute("UPDATE nodes SET active=0 WHERE id=?",(int(node_id),))

def node_by_token(token):
    h=_token_hash(token)
    with connect() as con:
        row=con.execute("SELECT id,name,active FROM nodes WHERE token_hash=? AND active=1",(h,)).fetchone()
        return dict(row) if row else None

def update_node_heartbeat(node_id,hostname,version,cpu,memory,disk):
    with connect() as con:
        con.execute(
            "UPDATE nodes SET last_seen_at=?,hostname=?,version=?,cpu=?,memory=?,disk=? WHERE id=?",
            (now(),hostname,version,float(cpu),float(memory),float(disk),int(node_id))
        )


def get_setting(key, default=None):
    with connect() as con:
        row=con.execute("SELECT value FROM settings WHERE key=?",(str(key),)).fetchone()
        return row["value"] if row else default

def set_setting(key, value):
    with connect() as con:
        con.execute(
            """INSERT INTO settings(key,value) VALUES(?,?)
               ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
            (str(key), str(value))
        )

def all_settings():
    with connect() as con:
        return {r["key"]:r["value"] for r in con.execute("SELECT key,value FROM settings").fetchall()}


def create_protocol_client(name,engine,protocol,inbound_tag,credential,share_link,quota_bytes=0,expire_at=0,ip_limit=1):
    ts=now()
    with connect() as con:
        cur=con.execute(
            """INSERT INTO protocol_clients(name,engine,protocol,inbound_tag,credential,share_link,quota_bytes,expire_at,ip_limit,enabled,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,1,?,?)""",
            (name,engine,protocol,inbound_tag,credential,share_link,max(0,int(quota_bytes or 0)),
             max(0,int(expire_at or 0)),max(1,int(ip_limit or 1)),ts,ts)
        )
        return cur.lastrowid

def list_protocol_clients():
    with connect() as con:
        rows=con.execute("SELECT * FROM protocol_clients ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

def get_protocol_client(client_id):
    with connect() as con:
        row=con.execute("SELECT * FROM protocol_clients WHERE id=?",(int(client_id),)).fetchone()
        return dict(row) if row else None

def update_protocol_client_state(client_id,enabled=None,quota_bytes=None,expire_at=None,ip_limit=None):
    fields=[]; values=[]
    if enabled is not None: fields.append("enabled=?"); values.append(1 if enabled else 0)
    if quota_bytes is not None: fields.append("quota_bytes=?"); values.append(max(0,int(quota_bytes)))
    if expire_at is not None: fields.append("expire_at=?"); values.append(max(0,int(expire_at)))
    if ip_limit is not None: fields.append("ip_limit=?"); values.append(max(1,int(ip_limit)))
    if not fields: return
    fields.append("updated_at=?"); values.append(now()); values.append(int(client_id))
    with connect() as con:
        con.execute("UPDATE protocol_clients SET "+",".join(fields)+" WHERE id=?",values)

def delete_protocol_client(client_id):
    with connect() as con:
        con.execute("DELETE FROM protocol_clients WHERE id=?",(int(client_id),))

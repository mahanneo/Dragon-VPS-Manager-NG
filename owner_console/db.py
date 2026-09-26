import os, sqlite3
from datetime import datetime, timezone
from .config import DB_PATH

def now(): return datetime.now(timezone.utc).isoformat()

def connect():
    DB_PATH.parent.mkdir(parents=True,exist_ok=True)
    con=sqlite3.connect(DB_PATH)
    con.row_factory=sqlite3.Row
    try: os.chmod(DB_PATH,0o600)
    except OSError: pass
    return con

def init_db():
    with connect() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS customers(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          contact TEXT NOT NULL DEFAULT '',
          note TEXT NOT NULL DEFAULT '',
          active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS installations(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          customer_id INTEGER,
          installation_id TEXT UNIQUE NOT NULL,
          domain TEXT NOT NULL DEFAULT '',
          note TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL,
          FOREIGN KEY(customer_id) REFERENCES customers(id)
        );
        CREATE TABLE IF NOT EXISTS licenses(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          license_id TEXT UNIQUE NOT NULL,
          customer_id INTEGER,
          installation_id TEXT NOT NULL,
          tier TEXT NOT NULL,
          features TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active',
          revision INTEGER NOT NULL DEFAULT 1,
          issued_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL DEFAULT 0,
          sync_token TEXT NOT NULL,
          current_code TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_licenses_installation ON licenses(installation_id);
        CREATE TABLE IF NOT EXISTS tickets(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          installation_id TEXT NOT NULL,
          version TEXT NOT NULL DEFAULT '',
          domain TEXT NOT NULL DEFAULT '',
          tier TEXT NOT NULL DEFAULT '',
          subject TEXT NOT NULL,
          message TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'open',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_logs(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          action TEXT NOT NULL,
          target TEXT NOT NULL DEFAULT '',
          detail TEXT NOT NULL DEFAULT '',
          ip TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL
        );
        """)

def audit(action,target="",detail="",ip=""):
    with connect() as con:
        con.execute("INSERT INTO audit_logs(action,target,detail,ip,created_at) VALUES(?,?,?,?,?)",(action,target,detail,ip,now()))

def create_customer(name,contact="",note=""):
    with connect() as con:
        cur=con.execute("INSERT INTO customers(name,contact,note,created_at) VALUES(?,?,?,?)",(name.strip(),contact.strip(),note.strip(),now()))
        return int(cur.lastrowid)

def customers():
    with connect() as con:return [dict(r) for r in con.execute("SELECT * FROM customers ORDER BY id DESC").fetchall()]

def customer(customer_id):
    with connect() as con:
        r=con.execute("SELECT * FROM customers WHERE id=?",(int(customer_id),)).fetchone()
        return dict(r) if r else None

def upsert_installation(customer_id,installation_id,domain="",note=""):
    installation_id=installation_id.strip().upper()
    with connect() as con:
        con.execute("""INSERT INTO installations(customer_id,installation_id,domain,note,created_at)
          VALUES(?,?,?,?,?) ON CONFLICT(installation_id) DO UPDATE SET
          customer_id=excluded.customer_id,domain=excluded.domain,note=excluded.note""",
          (customer_id,installation_id,domain.strip(),note.strip(),now()))
        r=con.execute("SELECT id FROM installations WHERE installation_id=?",(installation_id,)).fetchone()
        return int(r["id"])

def installations():
    with connect() as con:
        return [dict(r) for r in con.execute("""SELECT i.*,c.name customer_name FROM installations i
          LEFT JOIN customers c ON c.id=i.customer_id ORDER BY i.id DESC""").fetchall()]

def installation(installation_id):
    with connect() as con:
        r=con.execute("SELECT * FROM installations WHERE installation_id=?",(str(installation_id).strip().upper(),)).fetchone()
        return dict(r) if r else None

def save_license(item):
    with connect() as con:
        con.execute("""INSERT INTO licenses(license_id,customer_id,installation_id,tier,features,status,revision,issued_at,expires_at,sync_token,current_code,created_at,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
          (item["license_id"],item.get("customer_id"),item["installation_id"],item["tier"],item["features"],item["status"],item["revision"],item["issued_at"],item["expires_at"],item["sync_token"],item["current_code"],now(),now()))

def license_by_public(license_id,installation_id):
    with connect() as con:
        r=con.execute("SELECT * FROM licenses WHERE license_id=? AND installation_id=?",(license_id,installation_id)).fetchone()
        return dict(r) if r else None

def license_by_id(license_id):
    with connect() as con:
        r=con.execute("SELECT * FROM licenses WHERE license_id=?",(license_id,)).fetchone()
        return dict(r) if r else None

def update_license(license_id,**values):
    allowed={"status","revision","issued_at","expires_at","sync_token","current_code","features","tier"}
    pairs=[(k,v) for k,v in values.items() if k in allowed]
    if not pairs:return
    sql="UPDATE licenses SET "+",".join(f"{k}=?" for k,_ in pairs)+",updated_at=? WHERE license_id=?"
    with connect() as con: con.execute(sql,[v for _,v in pairs]+[now(),license_id])

def licenses():
    with connect() as con:
        return [dict(r) for r in con.execute("""SELECT l.*,c.name customer_name FROM licenses l
          LEFT JOIN customers c ON c.id=l.customer_id ORDER BY l.id DESC""").fetchall()]

def add_ticket(payload):
    ts=now()
    with connect() as con:
        cur=con.execute("""INSERT INTO tickets(installation_id,version,domain,tier,subject,message,status,created_at,updated_at)
          VALUES(?,?,?,?,?,?,'open',?,?)""",
          (payload.get("installation_id",""),payload.get("version",""),payload.get("domain",""),payload.get("tier",""),payload.get("subject","")[:160],payload.get("message","")[:5000],ts,ts))
        return int(cur.lastrowid)

def tickets():
    with connect() as con:return [dict(r) for r in con.execute("SELECT * FROM tickets ORDER BY id DESC LIMIT 500").fetchall()]

def set_ticket_status(ticket_id,status):
    if status not in {"open","pending","closed"}:raise ValueError("invalid status")
    with connect() as con:con.execute("UPDATE tickets SET status=?,updated_at=? WHERE id=?",(status,now(),int(ticket_id)))

def audit_rows():
    with connect() as con:return [dict(r) for r in con.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200").fetchall()]

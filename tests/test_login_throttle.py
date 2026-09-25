import sqlite3
from app import db

def _setup(tmp_path, monkeypatch):
    path=tmp_path/"makia-test.db"
    monkeypatch.setattr(db,"DB_PATH",path)
    with db.connect() as con:
        con.execute("""CREATE TABLE login_rate_limits (
          ip TEXT PRIMARY KEY,
          failures INTEGER NOT NULL DEFAULT 0,
          window_started INTEGER NOT NULL DEFAULT 0,
          blocked_until INTEGER NOT NULL DEFAULT 0
        )""")
    return path

def test_login_failures_eventually_block(tmp_path, monkeypatch):
    _setup(tmp_path,monkeypatch)
    state=None
    for i in range(6):
        state=db.record_login_failure("192.0.2.10",1000+i)
    assert state["failures"] == 6
    assert state["blocked_until"] > 1005
    read=db.login_rate_state("192.0.2.10",1006)
    assert read["blocked_until"] > 1006

def test_success_clears_throttle(tmp_path, monkeypatch):
    _setup(tmp_path,monkeypatch)
    db.record_login_failure("192.0.2.11",1000)
    db.clear_login_failures("192.0.2.11")
    state=db.login_rate_state("192.0.2.11",1001)
    assert state["failures"] == 0

def test_database_file_is_owner_only(tmp_path, monkeypatch):
    path=tmp_path/"perm.db"
    monkeypatch.setattr(db,"DB_PATH",path)
    con=db.connect(); con.close()
    assert (path.stat().st_mode & 0o777) == 0o600

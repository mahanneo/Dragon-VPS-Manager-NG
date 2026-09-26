import os, time
from app import db

def test_remote_support_code_is_one_time_and_revocable(tmp_path,monkeypatch):
    monkeypatch.setattr(db,"DB_PATH",tmp_path/"makia.db")
    monkeypatch.setenv("MAKIA_INITIAL_ADMIN_PASSWORD","StrongInitialPass!123")
    db.init_db()
    grant=db.create_support_grant("admin",minutes=30,scope="operator")
    assert grant["code"].startswith("SUP-")
    first=db.consume_support_grant(grant["code"].lower())
    assert first and first["scope"]=="operator"
    assert db.consume_support_grant(grant["code"]) is None
    state=db.support_grant_by_id(grant["id"])
    assert state["active"] is True
    db.revoke_support_grant(grant["id"])
    assert db.support_grant_by_id(grant["id"])["active"] is False

def test_new_support_grant_revokes_previous_active_grant(tmp_path,monkeypatch):
    monkeypatch.setattr(db,"DB_PATH",tmp_path/"makia.db")
    monkeypatch.setenv("MAKIA_INITIAL_ADMIN_PASSWORD","StrongInitialPass!123")
    db.init_db()
    one=db.create_support_grant("admin",30,"readonly")
    two=db.create_support_grant("admin",30,"operator")
    rows=db.list_support_grants()
    first=next(x for x in rows if x["id"]==one["id"])
    second=next(x for x in rows if x["id"]==two["id"])
    assert first["active"] is False
    assert second["active"] is True

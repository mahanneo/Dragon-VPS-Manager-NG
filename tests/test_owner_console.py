from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from owner_console import db, license_service
from app import license_ops

def test_owner_console_issue_renew_revoke_cycle(tmp_path,monkeypatch):
    private=Ed25519PrivateKey.generate()
    key_path=tmp_path/"owner.pem"
    key_path.write_bytes(private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    pub_path=tmp_path/"pub.pem"
    pub_path.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setattr(db,"DB_PATH",tmp_path/"owner.db")
    monkeypatch.setattr(license_service,"PRIVATE_KEY_PATH",key_path)
    monkeypatch.setattr(license_service,"PUBLIC_URL","https://owner.example.com")
    monkeypatch.setattr(license_ops,"DEFAULT_PUBLIC_KEY_PATH",pub_path)
    monkeypatch.setattr(license_ops,"installation_id",lambda:"MK-0123456789ABCDEF0123")
    db.init_db()
    cid=db.create_customer("Customer","@contact","")
    db.upsert_installation(cid,"MK-0123456789ABCDEF0123","vpn.example.com","")
    item=license_service.issue(cid,"MK-0123456789ABCDEF0123","Customer",30,"full")
    local=license_ops.verify_license(item["code"])
    assert local["online_required"] is True
    lease=license_service.lease(local["installation_id"],local["license_id"],local["sync_token"],local["revision"])
    state=license_ops.license_status(item["code"],lease["lease_code"])
    assert state["valid"] is True
    renewed=license_service.renew(item["license_id"],30)
    update=license_service.lease(local["installation_id"],local["license_id"],local["sync_token"],1)
    assert update["replacement_license_code"]==renewed["current_code"]
    assert update["revision"]==2
    license_service.revoke(item["license_id"])
    revoked=license_service.lease(local["installation_id"],local["license_id"],local["sync_token"],2)
    assert license_ops.license_status(renewed["current_code"],revoked["lease_code"])["valid"] is False

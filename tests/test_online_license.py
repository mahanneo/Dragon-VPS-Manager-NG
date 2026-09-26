import base64, json, time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app import license_ops

def b64u(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def sign(key,prefix,payload):
    raw=json.dumps(payload,sort_keys=True,separators=(",",":")).encode()
    return prefix+"."+b64u(raw)+"."+b64u(key.sign(raw))

def setup_key(tmp_path,monkeypatch):
    key=Ed25519PrivateKey.generate()
    pub=tmp_path/"pub.pem"
    pub.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setattr(license_ops,"DEFAULT_PUBLIC_KEY_PATH",pub)
    monkeypatch.setattr(license_ops,"installation_id",lambda:"MK-0123456789ABCDEF0123")
    return key

def online_license(key,now):
    return sign(key,"MKL1",{
        "v":1,"license_id":"LIC-ONLINE","customer":"Customer",
        "installation_id":"MK-0123456789ABCDEF0123","tier":"full",
        "features":sorted(license_ops.FULL_FEATURES),
        "issued_at":now,"not_before":now-60,"expires_at":now+86400*30,
        "revision":1,"online_required":True,"control_plane_url":"https://owner.example.com",
        "sync_token":"sync-secret","lease_grace_seconds":259200,
    })

def test_online_license_active_revoked_and_grace(tmp_path,monkeypatch):
    key=setup_key(tmp_path,monkeypatch);now=1_800_000_000
    code=online_license(key,now)
    active=sign(key,"MKLEASE1",{
        "v":1,"license_id":"LIC-ONLINE","installation_id":"MK-0123456789ABCDEF0123",
        "status":"active","revision":1,"issued_at":now,"expires_at":now+3600,
    })
    state=license_ops.license_status(code,active,now_ts=now+100)
    assert state["valid"] is True and state["online_status"]=="active"
    grace=license_ops.license_status(code,active,now_ts=now+7200)
    assert grace["valid"] is True and grace["online_status"]=="grace"
    revoked=sign(key,"MKLEASE1",{
        "v":1,"license_id":"LIC-ONLINE","installation_id":"MK-0123456789ABCDEF0123",
        "status":"revoked","revision":1,"issued_at":now,"expires_at":now+3600,
    })
    state=license_ops.license_status(code,revoked,now_ts=now+100)
    assert state["valid"] is False and state["online_status"]=="revoked"

def test_online_license_bootstrap_window_then_requires_lease(tmp_path,monkeypatch):
    key=setup_key(tmp_path,monkeypatch);now=1_800_000_000
    code=online_license(key,now)
    early=license_ops.license_status(code,"",now_ts=now+300)
    assert early["valid"] is True and early["online_status"]=="bootstrap"
    late=license_ops.license_status(code,"",now_ts=now+22000)
    assert late["valid"] is False and late["online_status"]=="pending"

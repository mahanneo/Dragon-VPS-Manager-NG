import io
import pytest
import pyzipper
from starlette.requests import Request

from app import access_ops
from app import main as main_app


def test_encrypted_payload_roundtrip(monkeypatch):
    monkeypatch.setattr(access_ops, "ensure_secret", lambda: b"x"*48)
    original={
        "native_filename":"client.conf",
        "files":{"client.conf":b"[Interface]\nPrivateKey = secret\n"},
        "summary":{"protocol":"wireguard"},
    }
    token=access_ops.seal_payload(original)
    assert "PrivateKey" not in token
    restored=access_ops.open_payload(token)
    assert restored["files"]["client.conf"] == original["files"]["client.conf"]
    assert restored["summary"]["protocol"] == "wireguard"


def test_protected_zip_requires_password():
    data=access_ops.protected_zip({"credentials.txt":b"top-secret"},"583921")
    assert b"top-secret" not in data
    verified=access_ops.verify_protected_zip(data,"583921","credentials.txt")
    assert verified["ok"] is True
    assert verified["sample_size"] == len(b"top-secret")
    with pyzipper.AESZipFile(io.BytesIO(data),"r") as zf:
        zf.setpassword(b"583921")
        assert zf.read("credentials.txt") == b"top-secret"


def test_protected_zip_rejects_wrong_password():
    data=access_ops.protected_zip({"credentials.txt":b"top-secret"},"583921")
    with pytest.raises(access_ops.AccessPackageError):
        access_ops.verify_protected_zip(data,"000000","credentials.txt")


def test_access_package_endpoint_returns_downloadable_aes_zip(monkeypatch):
    payload={
        "native_filename":"credentials.txt",
        "files":{"credentials.txt":b"server=example\npassword=secret\n"},
        "primary_text":"server=example",
        "summary":{},
    }
    monkeypatch.setattr(main_app,"require_mutation",lambda request:"admin")
    monkeypatch.setattr(main_app,"_resolve_access_payload",lambda kind,key,request:(payload,{"id":1}))
    monkeypatch.setattr(main_app,"audit",lambda *args,**kwargs:None)
    scope={
        "type":"http","method":"POST","path":"/api/access/ssh/u/package",
        "headers":[],"query_string":b"","scheme":"http",
        "server":("testserver",80),"client":("127.0.0.1",12345),
    }
    request=Request(scope)
    response=main_app.access_package("ssh","u",main_app.AccessPackageRequest(password="739251"),request)
    assert response.status_code == 200
    assert response.media_type == "application/zip"
    assert response.headers["cache-control"] == "no-store, private"
    assert "attachment;" in response.headers["content-disposition"]
    verified=access_ops.verify_protected_zip(response.body,"739251","credentials.txt")
    assert verified["ok"] is True


def test_ssh_package_does_not_embed_password_in_openssh_config():
    payload=access_ops.ssh_payload("vpn.example.com","user001","123456",22)
    config=payload["files"]["user001-ssh-config.txt"].decode()
    credentials=payload["files"]["credentials.txt"].decode()
    assert "123456" not in config
    assert "Password: 123456" in credentials


def test_xray_package_contains_qr_and_profile():
    payload=access_ops.xray_payload("u1","vless","vless://abc@example.com:443","https://example.com/sub/a","https://example.com/client/a")
    assert "u1-vless.txt" in payload["files"]
    assert "u1-profile.json" in payload["files"]
    assert "u1-qr.svg" in payload["files"]

import io
import pyzipper

from app import access_ops


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
    with pyzipper.AESZipFile(io.BytesIO(data),"r") as zf:
        zf.setpassword(b"583921")
        assert zf.read("credentials.txt") == b"top-secret"


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

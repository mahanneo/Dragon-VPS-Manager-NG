import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import license_ops


def _issue(private,installation_id="MK-TEST",days=30,features=None,tier="full"):
    now=int(time.time())
    payload={
        "v":1,
        "license_id":"LIC-TEST",
        "customer":"pytest",
        "installation_id":installation_id,
        "tier":tier,
        "features":sorted(features or license_ops.FULL_FEATURES),
        "issued_at":now,
        "not_before":now-60,
        "expires_at":0 if days==0 else now+days*86400,
    }
    raw=json.dumps(payload,sort_keys=True,separators=(",",":")).encode()
    b64=lambda x: base64.urlsafe_b64encode(x).decode().rstrip("=")
    return "MKL1."+b64(raw)+"."+b64(private.sign(raw))


@pytest.fixture()
def signing(monkeypatch,tmp_path):
    private=Ed25519PrivateKey.generate()
    public_path=tmp_path/"license-public.pem"
    public_path.write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    monkeypatch.setenv("MAKIA_LICENSE_PUBLIC_KEY_PATH",str(public_path))
    monkeypatch.setattr(license_ops,"installation_id",lambda:"MK-TEST")
    return private


def test_community_mode_is_ssh_only_by_default(signing):
    state=license_ops.license_status("")
    assert state["valid"] is False
    assert state["tier"]=="community"
    assert "ssh" in state["features"]
    assert "xray" not in state["features"]
    assert "openvpn" not in state["features"]


def test_full_signed_license_unlocks_premium_features(signing):
    code=_issue(signing)
    state=license_ops.verify_license(code)
    assert state["valid"] is True
    assert state["tier"]=="full"
    for feature in ["xray","wireguard","openvpn","protected_delivery","portable_migration","nodes"]:
        assert feature in state["features"]


def test_license_is_bound_to_installation(signing):
    code=_issue(signing,installation_id="MK-OTHER")
    with pytest.raises(license_ops.LicenseError,match="different Makia installation"):
        license_ops.verify_license(code)


def test_tampered_license_signature_is_rejected(signing):
    code=_issue(signing)
    parts=code.split(".")
    parts[1]=parts[1][:-1]+("A" if parts[1][-1]!="A" else "B")
    with pytest.raises(license_ops.LicenseError):
        license_ops.verify_license(".".join(parts))


def test_expired_license_falls_back_to_community(signing):
    now=int(time.time())
    payload={
        "v":1,"license_id":"LIC-OLD","customer":"pytest","installation_id":"MK-TEST","tier":"full",
        "features":sorted(license_ops.FULL_FEATURES),"issued_at":now-1000,"not_before":now-1000,"expires_at":now-1,
    }
    raw=json.dumps(payload,sort_keys=True,separators=(",",":")).encode()
    b64=lambda x: base64.urlsafe_b64encode(x).decode().rstrip("=")
    code="MKL1."+b64(raw)+"."+b64(signing.sign(raw))
    state=license_ops.license_status(code)
    assert state["valid"] is False
    assert state["tier"]=="community"
    assert "ssh" in state["features"]
    assert "xray" not in state["features"]
    assert "expired" in state["error"]

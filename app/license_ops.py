import base64
import hashlib
import json
import os
import platform
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .config import BASE_DIR

LICENSE_PREFIX="MKL1"
FULL_FEATURES={
    "xray","wireguard","openvpn","protected_delivery","subscriptions",
    "backups","portable_migration","nodes","advanced_services"
}
COMMUNITY_FEATURES={"ssh","security","domain","updates","support"}
DEFAULT_PUBLIC_KEY_PATH=BASE_DIR/"app"/"license_public_key.pem"


class LicenseError(RuntimeError):
    pass


def _b64u_decode(value:str)->bytes:
    value=str(value or "").strip()
    return base64.urlsafe_b64decode(value+"="*(-len(value)%4))


def _load_public_key()->Ed25519PublicKey:
    override=(os.getenv("MAKIA_LICENSE_PUBLIC_KEY_PATH") or "").strip()
    path=Path(override) if override else DEFAULT_PUBLIC_KEY_PATH
    data=path.read_bytes()
    key=serialization.load_pem_public_key(data)
    if not isinstance(key,Ed25519PublicKey):
        raise LicenseError("license verification key is not Ed25519")
    return key


def installation_id()->str:
    sources=[
        Path("/etc/machine-id"),
        Path("/var/lib/dbus/machine-id"),
    ]
    raw=""
    for path in sources:
        try:
            raw=path.read_text(encoding="utf-8").strip()
        except Exception:
            raw=""
        if raw:
            break
    if not raw:
        raw=platform.node() or "unknown-host"
    digest=hashlib.sha256(("makia-license-v1|"+raw).encode()).hexdigest().upper()
    return "MK-"+digest[:20]


def verify_license(code:str,now_ts:int|None=None)->dict:
    code=str(code or "").strip()
    if not code:
        raise LicenseError("license code is empty")
    parts=code.split(".")
    if len(parts)!=3 or parts[0]!=LICENSE_PREFIX:
        raise LicenseError("invalid license code format")
    payload_raw=_b64u_decode(parts[1])
    signature=_b64u_decode(parts[2])
    try:
        _load_public_key().verify(signature,payload_raw)
    except (InvalidSignature,ValueError,TypeError) as exc:
        raise LicenseError("license signature is invalid") from exc
    try:
        payload=json.loads(payload_raw.decode("utf-8"))
    except Exception as exc:
        raise LicenseError("license payload is invalid") from exc
    if not isinstance(payload,dict):
        raise LicenseError("license payload is invalid")
    expected=installation_id()
    if str(payload.get("installation_id") or "")!=expected:
        raise LicenseError("license belongs to a different Makia installation")
    now=int(now_ts if now_ts is not None else time.time())
    not_before=int(payload.get("not_before") or 0)
    expires_at=int(payload.get("expires_at") or 0)
    if not_before and now<not_before:
        raise LicenseError("license is not active yet")
    if expires_at and now>=expires_at:
        raise LicenseError("license has expired")
    tier=str(payload.get("tier") or "full").lower()
    declared={str(x).strip().lower() for x in (payload.get("features") or []) if str(x).strip()}
    features=set(FULL_FEATURES if tier=="full" and not declared else declared)
    features|=COMMUNITY_FEATURES
    return {
        "valid":True,
        "tier":tier,
        "license_id":str(payload.get("license_id") or ""),
        "customer":str(payload.get("customer") or ""),
        "installation_id":expected,
        "issued_at":int(payload.get("issued_at") or 0),
        "expires_at":expires_at,
        "features":sorted(features),
    }


def license_status(code:str|None)->dict:
    base={
        "valid":False,
        "tier":"community",
        "license_id":"",
        "customer":"",
        "installation_id":installation_id(),
        "issued_at":0,
        "expires_at":0,
        "features":sorted(COMMUNITY_FEATURES),
        "error":"",
    }
    if not str(code or "").strip():
        return base
    try:
        return {**base,**verify_license(str(code))}
    except LicenseError as exc:
        base["error"]=str(exc)
        return base


def has_feature(code:str|None,feature:str)->bool:
    feature=str(feature or "").strip().lower()
    return feature in set(license_status(code).get("features") or [])

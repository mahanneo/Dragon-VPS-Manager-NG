import base64
import hashlib
import json
import os
import platform
import time
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .config import BASE_DIR

LICENSE_PREFIX="MKL1"
LEASE_PREFIX="MKLEASE1"
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
        "revision":int(payload.get("revision") or 1),
        "online_required":bool(payload.get("online_required")),
        "control_plane_url":str(payload.get("control_plane_url") or "").rstrip("/"),
        "sync_token":str(payload.get("sync_token") or ""),
        "lease_grace_seconds":max(3600,min(int(payload.get("lease_grace_seconds") or 259200),604800)),
    }


def verify_lease(code:str,license_state:dict,now_ts:int|None=None)->dict:
    code=str(code or "").strip()
    parts=code.split(".")
    if len(parts)!=3 or parts[0]!=LEASE_PREFIX:
        raise LicenseError("invalid online lease format")
    payload_raw=_b64u_decode(parts[1])
    signature=_b64u_decode(parts[2])
    try:
        _load_public_key().verify(signature,payload_raw)
    except (InvalidSignature,ValueError,TypeError) as exc:
        raise LicenseError("online lease signature is invalid") from exc
    try:
        payload=json.loads(payload_raw.decode("utf-8"))
    except Exception as exc:
        raise LicenseError("online lease payload is invalid") from exc
    if str(payload.get("license_id") or "")!=str(license_state.get("license_id") or ""):
        raise LicenseError("online lease belongs to a different license")
    if str(payload.get("installation_id") or "")!=str(license_state.get("installation_id") or ""):
        raise LicenseError("online lease belongs to a different installation")
    return {
        "status":str(payload.get("status") or "unknown"),
        "issued_at":int(payload.get("issued_at") or 0),
        "expires_at":int(payload.get("expires_at") or 0),
        "revision":int(payload.get("revision") or 1),
    }

def license_status(code:str|None,lease_code:str|None=None,now_ts:int|None=None)->dict:
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
        "online_required":False,
        "online_status":"offline",
        "lease_expires_at":0,
    }
    if not str(code or "").strip():
        return base
    now=int(now_ts if now_ts is not None else time.time())
    try:
        verified=verify_license(str(code),now)
    except LicenseError as exc:
        base["error"]=str(exc)
        return base
    if not verified.get("online_required"):
        return {**base,**verified,"online_status":"not_required"}
    grace=int(verified.get("lease_grace_seconds") or 259200)
    if lease_code:
        try:
            lease=verify_lease(str(lease_code),verified,now)
            if lease["status"]=="revoked":
                return {**base,"license_id":verified["license_id"],"customer":verified["customer"],"online_required":True,"online_status":"revoked","error":"license has been revoked"}
            if lease["status"]!="active":
                raise LicenseError("online lease is not active")
            lease_exp=int(lease.get("expires_at") or 0)
            if now<lease_exp:
                return {**base,**verified,"online_status":"active","lease_expires_at":lease_exp}
            if now<lease_exp+grace:
                return {**base,**verified,"online_status":"grace","lease_expires_at":lease_exp}
            return {**base,"license_id":verified["license_id"],"customer":verified["customer"],"online_required":True,"online_status":"expired","error":"online license lease expired"}
        except LicenseError as exc:
            base["error"]=str(exc)
    bootstrap_until=int(verified.get("issued_at") or 0)+min(grace,21600)
    if now<=bootstrap_until:
        return {**base,**verified,"online_status":"bootstrap"}
    return {**base,"license_id":verified["license_id"],"customer":verified["customer"],"online_required":True,"online_status":"pending","error":base.get("error") or "online license verification required"}

def fetch_online_lease(code:str,timeout=6)->dict:
    state=verify_license(code)
    if not state.get("online_required"):
        return {"required":False}
    base=str(state.get("control_plane_url") or "").rstrip("/")
    token=str(state.get("sync_token") or "")
    if not base or not token:
        raise LicenseError("online license is missing control-plane settings")
    parsed=urllib.parse.urlparse(base)
    insecure_local=parsed.scheme=="http" and parsed.hostname in {"127.0.0.1","localhost","::1"}
    if parsed.scheme!="https" and not insecure_local:
        raise LicenseError("control-plane URL must use HTTPS")
    body=json.dumps({
        "installation_id":state["installation_id"],
        "license_id":state["license_id"],
        "sync_token":token,
        "revision":int(state.get("revision") or 1),
    },separators=(",",":")).encode("utf-8")
    request=urllib.request.Request(
        base+"/api/public/license/lease",
        data=body,
        headers={"Content-Type":"application/json","User-Agent":"Makia-License-Sync/1"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request,timeout=max(2,min(int(timeout),15))) as response:
            payload=json.loads(response.read(65536).decode("utf-8"))
    except Exception as exc:
        raise LicenseError(f"control-plane sync failed: {exc}") from exc
    lease_code=str(payload.get("lease_code") or "")
    lease=verify_lease(lease_code,state)
    replacement=str(payload.get("replacement_license_code") or "")
    if replacement:
        new_state=verify_license(replacement)
        if new_state["installation_id"]!=state["installation_id"] or new_state["license_id"]!=state["license_id"]:
            raise LicenseError("control-plane replacement license mismatch")
    return {"required":True,"lease_code":lease_code,"lease":lease,"replacement_license_code":replacement}


def has_feature(code:str|None,feature:str)->bool:
    feature=str(feature or "").strip().lower()
    return feature in set(license_status(code).get("features") or [])

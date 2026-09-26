import base64, hashlib, hmac, json, secrets, time
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .config import PRIVATE_KEY_PATH, PUBLIC_URL, LEASE_TTL_SECONDS, LEASE_GRACE_SECONDS
from . import db

LICENSE_PREFIX="MKL1"
LEASE_PREFIX="MKLEASE1"
FULL_FEATURES=[
    "xray","wireguard","openvpn","protected_delivery","subscriptions",
    "backups","portable_migration","nodes","advanced_services"
]

def _b64u(data:bytes)->str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def _load_key():
    key=serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(),password=None)
    if not isinstance(key,Ed25519PrivateKey):
        raise RuntimeError("owner signing key must be Ed25519")
    return key

def _sign(prefix,payload):
    raw=json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
    sig=_load_key().sign(raw)
    return prefix+"."+_b64u(raw)+"."+_b64u(sig)

def _feature_list(value):
    if not value or value=="full":return list(FULL_FEATURES),"full"
    if isinstance(value,str):
        items=[x.strip().lower() for x in value.split(",") if x.strip()]
    else:
        items=[str(x).strip().lower() for x in value if str(x).strip()]
    allowed=set(FULL_FEATURES)
    items=sorted(set(items)&allowed)
    if not items:raise ValueError("no valid premium features selected")
    return items,"custom"

def issue(customer_id,installation_id,customer_name,days=365,features="full"):
    if not PUBLIC_URL.startswith("https://"):
        raise RuntimeError("MAKIA_OWNER_PUBLIC_URL must be HTTPS before issuing online licenses")
    installation_id=str(installation_id or "").strip().upper()
    if not installation_id.startswith("MK-") or len(installation_id)<10:
        raise ValueError("invalid installation ID")
    feature_list,tier=_feature_list(features)
    now=int(time.time())
    expires=0 if int(days)==0 else now+max(1,int(days))*86400
    license_id="LIC-"+secrets.token_hex(6).upper()
    sync_token=secrets.token_urlsafe(32)
    payload={
        "v":1,"license_id":license_id,"customer":str(customer_name or "").strip(),
        "installation_id":installation_id,"tier":tier,"features":feature_list,
        "issued_at":now,"not_before":now-60,"expires_at":expires,
        "revision":1,"online_required":True,"control_plane_url":PUBLIC_URL,
        "sync_token":sync_token,"lease_grace_seconds":LEASE_GRACE_SECONDS,
    }
    code=_sign(LICENSE_PREFIX,payload)
    item={
        "license_id":license_id,"customer_id":customer_id,"installation_id":installation_id,
        "tier":tier,"features":",".join(feature_list),"status":"active","revision":1,
        "issued_at":now,"expires_at":expires,"sync_token":sync_token,"current_code":code,
    }
    db.save_license(item)
    return {**item,"code":code}

def _resign(record,days=None):
    now=int(time.time())
    features=[x for x in str(record.get("features") or "").split(",") if x]
    revision=int(record.get("revision") or 1)+1
    if days is None:
        expires=int(record.get("expires_at") or 0)
    else:
        expires=0 if int(days)==0 else now+max(1,int(days))*86400
    customer_row=db.customer(record.get("customer_id")) if record.get("customer_id") else None
    payload={
        "v":1,"license_id":record["license_id"],"customer":(customer_row or {}).get("name",""),
        "installation_id":record["installation_id"],"tier":record["tier"],"features":features,
        "issued_at":now,"not_before":now-60,"expires_at":expires,
        "revision":revision,"online_required":True,"control_plane_url":PUBLIC_URL,
        "sync_token":record["sync_token"],"lease_grace_seconds":LEASE_GRACE_SECONDS,
    }
    code=_sign(LICENSE_PREFIX,payload)
    db.update_license(record["license_id"],revision=revision,issued_at=now,expires_at=expires,current_code=code,status="active")
    return {**record,"revision":revision,"issued_at":now,"expires_at":expires,"current_code":code,"status":"active"}

def renew(license_id,days):
    record=db.license_by_id(license_id)
    if not record:raise ValueError("license not found")
    return _resign(record,days)

def revoke(license_id):
    record=db.license_by_id(license_id)
    if not record:raise ValueError("license not found")
    db.update_license(license_id,status="revoked")
    return {"ok":True,"license_id":license_id,"status":"revoked"}

def restore(license_id):
    record=db.license_by_id(license_id)
    if not record:raise ValueError("license not found")
    db.update_license(license_id,status="active")
    return {"ok":True,"license_id":license_id,"status":"active"}

def lease(installation_id,license_id,sync_token,revision=1):
    record=db.license_by_public(str(license_id),str(installation_id).upper())
    if not record or not hmac.compare_digest(str(record.get("sync_token") or ""),str(sync_token or "")):
        raise PermissionError("invalid installation/license sync credentials")
    now=int(time.time())
    status=str(record.get("status") or "revoked")
    if status=="active":
        exp=int(record.get("expires_at") or 0)
        if exp and now>=exp:status="expired"
    payload={
        "v":1,"license_id":record["license_id"],"installation_id":record["installation_id"],
        "status":"active" if status=="active" else "revoked",
        "revision":int(record.get("revision") or 1),
        "issued_at":now,"expires_at":now+LEASE_TTL_SECONDS,
    }
    lease_code=_sign(LEASE_PREFIX,payload)
    replacement=""
    if status=="active" and int(revision or 1)<int(record.get("revision") or 1):
        replacement=str(record.get("current_code") or "")
    return {"lease_code":lease_code,"replacement_license_code":replacement,"status":payload["status"],"revision":payload["revision"]}

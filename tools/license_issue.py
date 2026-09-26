#!/usr/bin/env python3
import argparse
import base64
import json
import secrets
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PREFIX="MKL1"
FULL_FEATURES=[
    "xray","wireguard","openvpn","protected_delivery","subscriptions",
    "backups","portable_migration","nodes","advanced_services"
]


def b64u(data:bytes)->str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def main():
    p=argparse.ArgumentParser(description="Issue a signed Makia full-access license.")
    p.add_argument("--private-key",required=True,help="Ed25519 PKCS8 PEM private key kept OFF the public repository")
    p.add_argument("--installation-id",required=True,help="MK-... ID shown in Support & License")
    p.add_argument("--customer",default="")
    p.add_argument("--days",type=int,default=365,help="0 means no expiry")
    p.add_argument("--license-id",default="")
    p.add_argument("--features",default="full",help="'full' or comma-separated feature names")
    args=p.parse_args()

    key=serialization.load_pem_private_key(Path(args.private_key).read_bytes(),password=None)
    if not isinstance(key,Ed25519PrivateKey):
        raise SystemExit("Private key must be Ed25519")
    now=int(time.time())
    if args.features.strip().lower()=="full":
        features=FULL_FEATURES
        tier="full"
    else:
        features=sorted({x.strip().lower() for x in args.features.split(",") if x.strip()})
        tier="custom"
    payload={
        "v":1,
        "license_id":args.license_id.strip() or ("LIC-"+secrets.token_hex(6).upper()),
        "customer":args.customer.strip(),
        "installation_id":args.installation_id.strip().upper(),
        "tier":tier,
        "features":features,
        "issued_at":now,
        "not_before":now-60,
        "expires_at":0 if args.days==0 else now+max(1,args.days)*86400,
    }
    raw=json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
    sig=key.sign(raw)
    print(PREFIX+"."+b64u(raw)+"."+b64u(sig))


if __name__=="__main__":
    main()

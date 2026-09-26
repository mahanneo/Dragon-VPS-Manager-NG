import base64
import hashlib
import io
import json
import re

from cryptography.fernet import Fernet, InvalidToken
import pyzipper
import qrcode
import qrcode.image.svg

from .security import ensure_secret

class AccessPackageError(RuntimeError):
    pass

def _fernet():
    key=hashlib.sha256(ensure_secret()+b"makia-access-artifact-v1").digest()
    return Fernet(base64.urlsafe_b64encode(key))

def _json_pack(value):
    if isinstance(value,(bytes,bytearray)):
        return {"__makia_bytes__":base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value,dict):
        return {str(k):_json_pack(v) for k,v in value.items()}
    if isinstance(value,list):
        return [_json_pack(v) for v in value]
    if isinstance(value,tuple):
        return [_json_pack(v) for v in value]
    return value

def _json_unpack(value):
    if isinstance(value,dict):
        if set(value)=={"__makia_bytes__"}:
            return base64.b64decode(value["__makia_bytes__"])
        return {k:_json_unpack(v) for k,v in value.items()}
    if isinstance(value,list):
        return [_json_unpack(v) for v in value]
    return value

def seal_payload(payload:dict)->str:
    raw=json.dumps(_json_pack(payload),ensure_ascii=False,separators=(",",":")).encode("utf-8")
    return _fernet().encrypt(raw).decode("ascii")

def open_payload(token:str)->dict:
    try:
        raw=_fernet().decrypt(str(token).encode("ascii"))
        obj=json.loads(raw.decode("utf-8"))
        obj=_json_unpack(obj)
        if not isinstance(obj,dict):
            raise AccessPackageError("invalid access payload")
        return obj
    except (InvalidToken,ValueError,TypeError,json.JSONDecodeError) as exc:
        raise AccessPackageError("unable to decrypt access payload") from exc

def safe_filename(value:str, fallback="access"):
    value=re.sub(r"[^A-Za-z0-9_.-]+","-",str(value or "")).strip(".-")
    return (value or fallback)[:96]

def make_qr_svg(text:str)->bytes:
    img=qrcode.make(text,image_factory=qrcode.image.svg.SvgPathImage)
    buf=io.BytesIO()
    img.save(buf)
    return buf.getvalue()

def npvt_ssh_link(host,username,password,port=22,remarks=None,dns_mode="UDP",udpgw_port=7300,transparent_dns=False):
    profile={
        "sshConfigType":"SSH-Direct",
        "remarks":str(remarks or f"Makia {username}"),
        "sshHost":str(host or "").strip(),
        "sshPort":int(port or 22),
        "sshUsername":str(username or "").strip(),
        "sshPassword":str(password or ""),
        "sni":"",
        "tlsVersion":"DEFAULT",
        "httpProxy":"",
        "authenticateProxy":False,
        "proxyUsername":"",
        "proxyPassword":"",
        "payload":"",
        "dnsTTMode":str(dns_mode or "UDP").upper(),
        "dnsServer":"",
        "nameserver":"",
        "publicKey":"",
        "udpgwPort":int(udpgw_port or 7300),
        "udpgwTransparentDNS":bool(transparent_dns),
    }
    raw=json.dumps(profile,ensure_ascii=False,separators=(",",":")).encode("utf-8")
    return "npvt-ssh://"+base64.b64encode(raw).decode("ascii")

def ssh_payload(host,username,password,port=22,npv_options=None):
    host=str(host or "").strip()
    username=str(username or "").strip()
    port=int(port or 22)
    config=(
        f"Host makia-{safe_filename(username)}\n"
        f"    HostName {host}\n"
        f"    User {username}\n"
        f"    Port {port}\n"
        "    ServerAliveInterval 30\n"
        "    ServerAliveCountMax 3\n"
    )
    opts=dict(npv_options or {})
    npv=npvt_ssh_link(
        host,username,password,port,
        remarks=opts.get("remarks") or f"Makia {username}",
        dns_mode=opts.get("dns_mode") or "UDP",
        udpgw_port=int(opts.get("udpgw_port") or 7300),
        transparent_dns=bool(opts.get("transparent_dns",False)),
    )
    credentials=(
        "Makia SSH Access\n"
        f"Server: {host}\n"
        f"Port: {port}\n"
        f"Username: {username}\n"
        f"Password: {password}\n"
        "\nNPV Tunnel / NapsternetV quick import:\n"
        f"{npv}\n"
        "\nOpenSSH does not support embedding passwords in config files.\n"
        "Use the OpenSSH fragment for regular SSH clients, or import the npvt-ssh link/QR in NPV Tunnel.\n"
    )
    npv_name=f"{safe_filename(username)}-npvt-ssh.txt"
    return {
        "native_filename":f"{safe_filename(username)}-ssh-config.txt",
        "files":{
            f"{safe_filename(username)}-ssh-config.txt":config.encode("utf-8"),
            "credentials.txt":credentials.encode("utf-8"),
            npv_name:(npv+"\n").encode("utf-8"),
            f"{safe_filename(username)}-npvt-qr.svg":make_qr_svg(npv),
        },
        "primary_text":credentials,
        "share_text":npv,
        "share_type":"npvt-ssh",
        "summary":{
            "host":host,"port":port,"username":username,
            "npv_link":npv,"npv_filename":npv_name,
            "npv_dns_mode":str(opts.get("dns_mode") or "UDP").upper(),
            "npv_udpgw_port":int(opts.get("udpgw_port") or 7300),
            "npv_transparent_dns":bool(opts.get("transparent_dns",False)),
        },
    }

def wireguard_payload(name,config,address=None):
    filename=f"{safe_filename(name)}.conf"
    return {
        "native_filename":filename,
        "files":{
            filename:str(config).encode("utf-8"),
            f"{safe_filename(name)}-qr.svg":make_qr_svg(str(config)),
        },
        "primary_text":str(config),
        "share_text":str(config),
        "share_type":"wireguard",
        "summary":{"address":address or ""},
    }

def openvpn_payload(name,config):
    filename=f"{safe_filename(name)}.ovpn"
    return {
        "native_filename":filename,
        "files":{filename:str(config).encode("utf-8")},
        "primary_text":str(config),
        "summary":{},
    }

def xray_payload(name,protocol,share_link,subscription_url=None,client_url=None):
    profile={
        "name":name,
        "protocol":protocol,
        "share_link":share_link,
        "subscription_url":subscription_url or "",
        "client_page":client_url or "",
    }
    filename=f"{safe_filename(name)}-{safe_filename(protocol)}.txt"
    lines=[
        "Makia Xray Access",
        f"Name: {name}",
        f"Protocol: {protocol}",
        "",
        "Share link:",
        str(share_link),
    ]
    if subscription_url:
        lines += ["","Subscription:",str(subscription_url)]
    if client_url:
        lines += ["","Client page:",str(client_url)]
    text="\n".join(lines)+"\n"
    files={
        filename:text.encode("utf-8"),
        f"{safe_filename(name)}-profile.json":json.dumps(profile,ensure_ascii=False,indent=2).encode("utf-8"),
        f"{safe_filename(name)}-qr.svg":make_qr_svg(str(share_link)),
    }
    return {
        "native_filename":filename,
        "files":files,
        "primary_text":str(share_link),
        "share_text":str(share_link),
        "share_type":"xray",
        "summary":{"protocol":protocol,"subscription_url":subscription_url or "","client_url":client_url or ""},
    }

def protected_zip(files:dict[str,bytes|str],password:str)->bytes:
    password=str(password or "")
    if len(password)<4:
        raise AccessPackageError("package password must be at least 4 characters")
    buf=io.BytesIO()
    with pyzipper.AESZipFile(buf,"w",compression=pyzipper.ZIP_DEFLATED,encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode("utf-8"))
        zf.setencryption(pyzipper.WZ_AES,nbits=256)
        for name,data in files.items():
            filename=safe_filename(name,"file")
            raw=data.encode("utf-8") if isinstance(data,str) else bytes(data)
            zf.writestr(filename,raw)
    return buf.getvalue()


def verify_protected_zip(blob:bytes,password:str,expected_name:str|None=None)->dict:
    try:
        with pyzipper.AESZipFile(io.BytesIO(bytes(blob)),"r") as zf:
            zf.setpassword(str(password).encode("utf-8"))
            names=zf.namelist()
            if not names:
                raise AccessPackageError("protected package is empty")
            target=expected_name if expected_name in names else names[0]
            sample=zf.read(target)
            return {"ok":True,"files":names,"sample_size":len(sample)}
    except Exception as exc:
        if isinstance(exc,AccessPackageError):
            raise
        raise AccessPackageError("protected package verification failed") from exc

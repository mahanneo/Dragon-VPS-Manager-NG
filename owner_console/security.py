import base64, hashlib, hmac, json, os, secrets, time
from .config import SECRET_PATH

def ensure_secret():
    SECRET_PATH.parent.mkdir(parents=True,exist_ok=True)
    if not SECRET_PATH.exists():
        SECRET_PATH.write_bytes(secrets.token_bytes(48))
        os.chmod(SECRET_PATH,0o600)
    return SECRET_PATH.read_bytes()

def hash_password(password):
    salt=secrets.token_bytes(16)
    digest=hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1,dklen=32)
    return "scrypt$"+base64.urlsafe_b64encode(salt).decode()+"$"+base64.urlsafe_b64encode(digest).decode()

def verify_password(password,encoded):
    try:
        _,salt_b64,digest_b64=encoded.split("$",2)
        salt=base64.urlsafe_b64decode(salt_b64)
        expected=base64.urlsafe_b64decode(digest_b64)
        actual=hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1,dklen=32)
        return hmac.compare_digest(actual,expected)
    except Exception:
        return False

def make_session(ttl=43200):
    payload={"k":"owner","exp":int(time.time())+max(300,min(int(ttl),86400)),"n":secrets.token_hex(12)}
    raw=base64.urlsafe_b64encode(json.dumps(payload,separators=(",",":")).encode()).decode().rstrip("=")
    sig=hmac.new(ensure_secret(),raw.encode(),hashlib.sha256).hexdigest()
    return raw+"."+sig

def valid_session(token):
    if not token or "." not in token:return False
    raw,sig=token.rsplit(".",1)
    expected=hmac.new(ensure_secret(),raw.encode(),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig,expected):return False
    try:
        payload=json.loads(base64.urlsafe_b64decode(raw+"="*(-len(raw)%4)).decode())
        return payload.get("k")=="owner" and int(payload.get("exp") or 0)>int(time.time())
    except Exception:
        return False

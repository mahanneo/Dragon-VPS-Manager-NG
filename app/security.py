import base64, hashlib, hmac, json, os, secrets, time
from .config import SECRET_PATH, SESSION_TTL_SECONDS

def ensure_secret() -> bytes:
    SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not SECRET_PATH.exists():
        SECRET_PATH.write_bytes(secrets.token_bytes(48))
        os.chmod(SECRET_PATH, 0o600)
    return SECRET_PATH.read_bytes()

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.urlsafe_b64encode(salt).decode() + "$" + base64.urlsafe_b64encode(digest).decode()

def verify_password(password: str, encoded: str) -> bool:
    try:
        _, salt_b64, digest_b64 = encoded.split("$", 2)
        salt = base64.urlsafe_b64decode(salt_b64)
        expected = base64.urlsafe_b64decode(digest_b64)
        actual = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False

def make_session(username: str, ttl_seconds: int | None = None) -> str:
    ttl=int(ttl_seconds or SESSION_TTL_SECONDS)
    ttl=max(300,min(ttl,60*60*24*30))
    payload = {"u": username, "exp": int(time.time()) + ttl, "n": secrets.token_hex(8)}
    raw = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    sig = hmac.new(ensure_secret(), raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"

def read_session(token: str | None) -> str | None:
    if not token or "." not in token:
        return None
    raw, sig = token.rsplit(".", 1)
    expected = hmac.new(ensure_secret(), raw.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        padded = raw + "=" * (-len(raw) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode())
        if int(payload["exp"]) < int(time.time()):
            return None
        return str(payload["u"])
    except Exception:
        return None


def make_preauth(username: str) -> str:
    payload = {"u": username, "exp": int(time.time()) + 300, "k": "2fa", "n": secrets.token_hex(8)}
    raw = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    sig = hmac.new(ensure_secret(), raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"

def read_preauth(token: str | None) -> str | None:
    if not token or "." not in token:
        return None
    raw, sig = token.rsplit(".", 1)
    expected = hmac.new(ensure_secret(), raw.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        padded = raw + "=" * (-len(raw) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode())
        if payload.get("k") != "2fa" or int(payload["exp"]) < int(time.time()):
            return None
        return str(payload["u"])
    except Exception:
        return None

import re
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from cryptography import x509

NGINX_SITE=Path("/etc/nginx/sites-available/makia-vps-manager")
DOMAIN_RE=re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$")
EMAIL_RE=re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

class PanelOperationError(RuntimeError):
    pass

def _run(args, timeout=120):
    try:
        p=subprocess.run(args,text=True,capture_output=True,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise PanelOperationError(str(exc)) from exc
    if p.returncode!=0:
        raise PanelOperationError((p.stderr or p.stdout or "operation failed").strip()[:1200])
    return p.stdout.strip()

def validate_domain(domain):
    domain=(domain or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(domain):
        raise PanelOperationError("invalid domain name")
    return domain

def domain_status(domain=None):
    resolved=[]
    if domain:
        try:
            resolved=sorted({x[4][0] for x in socket.getaddrinfo(domain,None,socket.AF_INET)})
        except Exception:
            resolved=[]
    cert_exists=False
    cert_expires_at=None
    cert_days_left=None
    if domain:
        cert_path=Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
        cert_exists=cert_path.exists()
        if cert_exists:
            try:
                cert=x509.load_pem_x509_certificate(cert_path.read_bytes())
                expires=getattr(cert,"not_valid_after_utc",None)
                if expires is None:
                    expires=cert.not_valid_after.replace(tzinfo=timezone.utc)
                cert_expires_at=expires.isoformat()
                cert_days_left=int((expires-datetime.now(timezone.utc)).total_seconds()//86400)
            except Exception:
                pass
    return {
        "domain":domain,
        "resolved_ipv4":resolved,
        "certificate":cert_exists,
        "certificate_expires_at":cert_expires_at,
        "certificate_days_left":cert_days_left,
        "certbot_installed":bool(shutil.which("certbot")),
        "nginx_site":str(NGINX_SITE),
    }

def apply_domain(domain):
    domain=validate_domain(domain)
    if not NGINX_SITE.exists():
        raise PanelOperationError("Makia Nginx site is not installed")
    original=NGINX_SITE.read_text(encoding="utf-8")
    backup=NGINX_SITE.with_suffix(".conf.makia-backup")
    backup.write_text(original,encoding="utf-8")
    if re.search(r"(?m)^\s*server_name\s+[^;]+;",original):
        updated=re.sub(r"(?m)^\s*server_name\s+[^;]+;",f"    server_name {domain};",original,count=1)
    else:
        updated=original.replace("server {","server {\n    server_name "+domain+";",1)
    NGINX_SITE.write_text(updated,encoding="utf-8")
    try:
        _run(["nginx","-t"],timeout=20)
        _run(["systemctl","reload","nginx"],timeout=20)
    except Exception:
        NGINX_SITE.write_text(original,encoding="utf-8")
        try:
            _run(["nginx","-t"],timeout=20)
            _run(["systemctl","reload","nginx"],timeout=20)
        except Exception:
            pass
        raise
    return domain_status(domain)

def issue_certificate(domain,email):
    domain=validate_domain(domain)
    email=(email or "").strip()
    if not EMAIL_RE.fullmatch(email):
        raise PanelOperationError("invalid email address")
    if not shutil.which("certbot"):
        _run(["apt-get","update"],timeout=180)
        _run(["apt-get","install","-y","certbot","python3-certbot-nginx"],timeout=300)
    _run([
        "certbot","--nginx","-d",domain,
        "--non-interactive","--agree-tos","--email",email,
        "--redirect"
    ],timeout=300)
    return domain_status(domain)

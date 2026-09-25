import os, pwd, shutil, socket, subprocess, platform
from datetime import datetime
import psutil
from .config import ALLOWED_SERVICES

class OperationError(RuntimeError): pass

def _run(args: list[str], input_text: str | None = None, timeout: int = 15):
    try:
        p = subprocess.run(args, input=input_text, text=True, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OperationError(str(exc)) from exc
    if p.returncode != 0:
        raise OperationError((p.stderr or p.stdout or "operation failed").strip()[:500])
    return p.stdout.strip()

def metrics():
    disk = psutil.disk_usage("/")
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    net = psutil.net_io_counters()
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "kernel": platform.release(),
        "cpu": psutil.cpu_percent(interval=0.15),
        "cpu_cores": psutil.cpu_count(logical=True) or 1,
        "memory": mem.percent,
        "memory_used": mem.used,
        "memory_total": mem.total,
        "swap": swap.percent,
        "disk": disk.percent,
        "disk_used": disk.used,
        "disk_total": disk.total,
        "load": list(os.getloadavg()) if hasattr(os, "getloadavg") else [0,0,0],
        "uptime_seconds": int(datetime.now().timestamp() - psutil.boot_time()),
        "network": {"sent": net.bytes_sent, "recv": net.bytes_recv},
    }

def online_sessions():
    sessions=[]
    try:
        out=_run(["who"], timeout=5)
    except Exception:
        return sessions
    for line in out.splitlines():
        parts=line.split()
        if not parts: continue
        username=parts[0]
        tty=parts[1] if len(parts)>1 else ""
        when=" ".join(parts[2:4]) if len(parts)>3 else ""
        remote=""
        if "(" in line and ")" in line:
            remote=line.rsplit("(",1)[-1].rstrip(")")
        sessions.append({"username":username,"tty":tty,"since":when,"remote":remote})
    return sessions

def service_status(name: str):
    if name not in ALLOWED_SERVICES:
        raise OperationError("service is not allowlisted")
    if not shutil.which("systemctl"):
        return {"name": name, "label": ALLOWED_SERVICES[name], "active": False, "state": "unsupported"}
    p = subprocess.run(["systemctl", "is-active", name], text=True, capture_output=True)
    state = (p.stdout or p.stderr).strip() or "unknown"
    return {"name": name, "label": ALLOWED_SERVICES[name], "active": p.returncode == 0, "state": state}

def service_action(name: str, action: str):
    if name not in ALLOWED_SERVICES or action not in {"start","stop","restart"}:
        raise OperationError("operation not allowed")
    _run(["systemctl", action, name])
    return service_status(name)

def ssh_users():
    users = []
    for entry in pwd.getpwall():
        if entry.pw_uid >= 1000 and entry.pw_shell not in {"/usr/sbin/nologin", "/bin/false"}:
            users.append({"username": entry.pw_name, "uid": entry.pw_uid, "home": entry.pw_dir, "shell": entry.pw_shell})
    return users

def validate_username(username: str):
    if not username or len(username) > 32 or not username.replace("-", "").replace("_", "").isalnum() or not username[0].isalpha():
        raise OperationError("invalid username")

def create_ssh_user(username: str, password: str, expire: str | None = None):
    validate_username(username)
    if len(password) < 10:
        raise OperationError("password must be at least 10 characters")
    args = ["useradd", "-m", "-s", "/bin/bash"]
    if expire: args += ["-e", expire]
    args.append(username)
    _run(args)
    try:
        _run(["chpasswd"], input_text=f"{username}:{password}\n")
    except Exception:
        subprocess.run(["userdel", "-r", username], capture_output=True)
        raise
    return {"username": username, "expire": expire}

def lock_user(username: str, locked: bool):
    validate_username(username)
    _run(["usermod", "-L" if locked else "-U", username])
    return {"username": username, "locked": locked}

def delete_user(username: str):
    validate_username(username)
    _run(["userdel", "-r", username])
    return {"username": username, "deleted": True}

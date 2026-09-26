import os, pwd, shutil, socket, subprocess, platform, re, time
import io, json, tarfile
from pathlib import Path
from datetime import datetime
import psutil
import pyzipper
from .config import ALLOWED_SERVICES

class OperationError(RuntimeError): pass

TTY_RE=re.compile(r"^[A-Za-z0-9._/-]{1,64}$")

def _run(args: list[str], input_text: str | None = None, timeout: int = 15):
    last_error = "operation failed"
    for attempt in range(3):
        try:
            p = subprocess.run(args, input=input_text, text=True, capture_output=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise OperationError(str(exc)) from exc
        if p.returncode == 0:
            return p.stdout.strip()
        last_error = (p.stderr or p.stdout or "operation failed").strip()[:500]
        # shadow-utils can briefly contend on /etc/.pwd.lock during package/user operations.
        if "cannot lock /etc/passwd" in last_error.lower() and attempt < 2:
            time.sleep(1.0 + attempt)
            continue
        break
    raise OperationError(last_error)

def metrics():
    disk=psutil.disk_usage("/")
    mem=psutil.virtual_memory()
    swap=psutil.swap_memory()
    net=psutil.net_io_counters()
    return {
        "hostname":socket.gethostname(),
        "platform":platform.platform(),
        "kernel":platform.release(),
        "cpu":psutil.cpu_percent(interval=0.15),
        "cpu_cores":psutil.cpu_count(logical=True) or 1,
        "memory":mem.percent,
        "memory_used":mem.used,
        "memory_total":mem.total,
        "swap":swap.percent,
        "disk":disk.percent,
        "disk_used":disk.used,
        "disk_total":disk.total,
        "load":list(os.getloadavg()) if hasattr(os,"getloadavg") else [0,0,0],
        "uptime_seconds":int(datetime.now().timestamp()-psutil.boot_time()),
        "network":{"sent":net.bytes_sent,"recv":net.bytes_recv},
    }

def online_sessions():
    sessions=[]
    try: out=_run(["who"],timeout=5)
    except Exception: return sessions
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

def disconnect_session(tty: str):
    if not TTY_RE.fullmatch(tty or ""):
        raise OperationError("invalid terminal")
    # Use pkill against an exact terminal only; no shell expansion.
    _run(["pkill","-KILL","-t",tty],timeout=8)
    return {"tty":tty,"disconnected":True}

def service_status(name: str):
    if name not in ALLOWED_SERVICES:
        raise OperationError("service is not allowlisted")
    if not shutil.which("systemctl"):
        return {"name":name,"label":ALLOWED_SERVICES[name],"active":False,"state":"unsupported"}
    p=subprocess.run(["systemctl","is-active",name],text=True,capture_output=True)
    state=(p.stdout or p.stderr).strip() or "unknown"
    return {"name":name,"label":ALLOWED_SERVICES[name],"active":p.returncode==0,"state":state}

def service_action(name: str, action: str):
    if name not in ALLOWED_SERVICES or action not in {"start","stop","restart"}:
        raise OperationError("operation not allowed")
    _run(["systemctl",action,name])
    return service_status(name)

def ssh_users():
    users=[]
    for entry in pwd.getpwall():
        if entry.pw_uid>=1000 and entry.pw_shell not in {"/usr/sbin/nologin","/bin/false"}:
            users.append({"username":entry.pw_name,"uid":entry.pw_uid,"home":entry.pw_dir,"shell":entry.pw_shell})
    return users

def validate_username(username: str):
    if not username or len(username)>32 or not username.replace("-","").replace("_","").isalnum() or not username[0].isalpha():
        raise OperationError("invalid username")

def validate_user_password(password: str):
    if len(password)<4:
        raise OperationError("password/PIN must be at least 4 characters")
    if len(password)>128:
        raise OperationError("password is too long")

def create_ssh_user(username: str,password: str,expire: str|None=None):
    validate_username(username); validate_user_password(password)
    args=["useradd","-m","-s","/bin/bash"]
    if expire: args+=["-e",expire]
    args.append(username)
    _run(args)
    try:
        _run(["chpasswd"],input_text=f"{username}:{password}\n")
    except Exception:
        subprocess.run(["userdel","-r",username],capture_output=True)
        raise
    return {"username":username,"expire":expire}

def update_ssh_user(username: str,password: str|None=None,expire: str|None=None,clear_expire: bool=False):
    validate_username(username)
    if password:
        validate_user_password(password)
        _run(["chpasswd"],input_text=f"{username}:{password}\n")
    if clear_expire:
        _run(["usermod","-e","",username])
    elif expire:
        _run(["usermod","-e",expire,username])
    return {"username":username,"updated":True}

def lock_user(username: str,locked: bool):
    validate_username(username)
    _run(["usermod","-L" if locked else "-U",username])
    return {"username":username,"locked":locked}

def delete_user(username: str):
    validate_username(username)
    _run(["userdel","-r",username])
    return {"username":username,"deleted":True}

def security_status():
    def cmd_state(binary,args):
        if not shutil.which(binary): return {"installed":False,"active":False,"detail":"not installed"}
        p=subprocess.run(args,text=True,capture_output=True)
        text=(p.stdout or p.stderr or "").strip()
        return {"installed":True,"active":p.returncode==0,"detail":text[:400]}
    ufw=cmd_state("ufw",["ufw","status"])
    fail2ban=cmd_state("systemctl",["systemctl","is-active","fail2ban"])
    ssh=cmd_state("systemctl",["systemctl","is-active","ssh"])
    return {"ufw":ufw,"fail2ban":fail2ban,"ssh":ssh}


def portable_backup_sources(data_dir: str):
    sources=[]
    data=Path(data_dir)
    if data.exists():
        sources.append((data,"data"))
    candidates=[
        (Path("/etc/wireguard"),"host/etc/wireguard"),
        (Path("/usr/local/etc/xray/config.json"),"host/usr/local/etc/xray/config.json"),
        (Path("/etc/xray/config.json"),"host/etc/xray/config.json"),
        (Path("/etc/openvpn"),"host/etc/openvpn"),
        (Path("/etc/nginx/sites-available/makia-vps-manager"),"host/etc/nginx/sites-available/makia-vps-manager"),
        (Path("/etc/letsencrypt"),"host/etc/letsencrypt"),
        (Path("/etc/fail2ban/jail.d/makia-sshd.local"),"host/etc/fail2ban/jail.d/makia-sshd.local"),
    ]
    seen=set()
    for src,arc in candidates:
        if src.exists() and str(src) not in seen:
            sources.append((src,arc));seen.add(str(src))
    return sources

def portable_backup_status(data_dir: str):
    sources=portable_backup_sources(data_dir)
    names=[arc for _,arc in sources]
    return {
        "sources":names,
        "has_data":"data" in names,
        "has_wireguard":"host/etc/wireguard" in names,
        "has_xray":any(x.endswith("/xray/config.json") for x in names),
        "has_openvpn":"host/etc/openvpn" in names,
        "has_nginx":"host/etc/nginx/sites-available/makia-vps-manager" in names,
        "has_letsencrypt":"host/etc/letsencrypt" in names,
    }

def create_portable_backup(data_dir: str, password: str, metadata=None, sources=None):
    password=str(password or "")
    if len(password)<8:
        raise OperationError("portable backup password must be at least 8 characters")
    chosen=list(sources) if sources is not None else portable_backup_sources(data_dir)
    if not chosen:
        raise OperationError("no portable backup sources are available")
    manifest={
        "format":"makia-portable-v1",
        "created_at":datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "metadata":metadata or {},
        "sources":[arc for _,arc in chosen],
        "restore_command":"sudo makia-restore /path/to/bundle.zip --apply",
    }
    tar_buf=io.BytesIO()
    try:
        with tarfile.open(fileobj=tar_buf,mode="w:gz") as tf:
            for src,arc in chosen:
                p=Path(src)
                if p.exists():
                    tf.add(str(p),arcname=arc,recursive=True)
    except Exception as exc:
        raise OperationError(f"unable to build portable archive: {exc}") from exc
    zip_buf=io.BytesIO()
    try:
        with pyzipper.AESZipFile(zip_buf,"w",compression=pyzipper.ZIP_DEFLATED,encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(password.encode("utf-8"))
            zf.setencryption(pyzipper.WZ_AES,nbits=256)
            zf.writestr("manifest.json",json.dumps(manifest,ensure_ascii=False,indent=2).encode("utf-8"))
            zf.writestr("makia-portable.tar.gz",tar_buf.getvalue())
    except Exception as exc:
        raise OperationError(f"unable to encrypt portable archive: {exc}") from exc
    blob=zip_buf.getvalue()
    return {"blob":blob,"manifest":manifest,"size":len(blob)}

def verify_portable_backup(blob: bytes, password: str):
    try:
        with pyzipper.AESZipFile(io.BytesIO(bytes(blob)),"r") as zf:
            zf.setpassword(str(password).encode("utf-8"))
            names=set(zf.namelist())
            if {"manifest.json","makia-portable.tar.gz"}-names:
                raise OperationError("portable backup is missing required files")
            manifest=json.loads(zf.read("manifest.json").decode("utf-8"))
            if manifest.get("format")!="makia-portable-v1":
                raise OperationError("unsupported portable backup format")
            tar_blob=zf.read("makia-portable.tar.gz")
        with tarfile.open(fileobj=io.BytesIO(tar_blob),mode="r:gz") as tf:
            for member in tf.getmembers():
                name=member.name
                if name.startswith("/") or ".." in Path(name).parts:
                    raise OperationError("unsafe path detected in portable backup")
            members=[m.name for m in tf.getmembers()]
        return {"ok":True,"manifest":manifest,"members":members}
    except OperationError:
        raise
    except Exception as exc:
        raise OperationError("portable backup verification failed") from exc

def backup_list():
    root="/var/backups/makia-vps-manager"
    if not os.path.isdir(root): return []
    items=[]
    for name in sorted(os.listdir(root),reverse=True):
        path=os.path.join(root,name)
        if os.path.isfile(path) and name.endswith(".tar.gz"):
            st=os.stat(path)
            items.append({"name":name,"size":st.st_size,"created_at":int(st.st_mtime)})
    return items[:50]

def create_backup(data_dir: str):
    root="/var/backups/makia-vps-manager"
    os.makedirs(root,mode=0o700,exist_ok=True)
    stamp=datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out=os.path.join(root,f"makia-data-{stamp}.tar.gz")
    if not os.path.isdir(data_dir):
        raise OperationError("data directory not found")
    _run(["tar","-C",os.path.dirname(data_dir),"-czf",out,os.path.basename(data_dir)],timeout=60)
    os.chmod(out,0o600)
    return {"name":os.path.basename(out),"path":out,"size":os.path.getsize(out)}

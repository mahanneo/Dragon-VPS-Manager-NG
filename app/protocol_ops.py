import json, os, shutil, subprocess

XRAY_BIN_CANDIDATES=["/usr/local/bin/xray","/usr/bin/xray"]
XRAY_CONFIG_CANDIDATES=["/usr/local/etc/xray/config.json","/etc/xray/config.json"]

def _binary():
    for p in XRAY_BIN_CANDIDATES:
        if os.path.isfile(p) and os.access(p,os.X_OK): return p
    return shutil.which("xray")

def _config_path():
    for p in XRAY_CONFIG_CANDIDATES:
        if os.path.isfile(p): return p
    return None

def status():
    binary=_binary()
    config=_config_path()
    version=None
    if binary:
        try:
            p=subprocess.run([binary,"version"],text=True,capture_output=True,timeout=5,check=False)
            version=(p.stdout or p.stderr).splitlines()[0][:160] if (p.stdout or p.stderr) else None
        except Exception:
            pass
    service_active=False
    if shutil.which("systemctl"):
        p=subprocess.run(["systemctl","is-active","xray"],text=True,capture_output=True)
        service_active=p.returncode==0
    inbounds=[]
    error=None
    if config:
        try:
            with open(config,"r",encoding="utf-8") as fh: data=json.load(fh)
            for item in data.get("inbounds",[]) if isinstance(data,dict) else []:
                if not isinstance(item,dict): continue
                settings=item.get("settings") or {}
                clients=settings.get("clients") if isinstance(settings,dict) else None
                inbounds.append({
                    "tag":item.get("tag") or "",
                    "protocol":item.get("protocol") or "unknown",
                    "listen":item.get("listen") or "0.0.0.0",
                    "port":item.get("port"),
                    "clients":len(clients) if isinstance(clients,list) else 0,
                })
        except Exception as exc:
            error=str(exc)[:300]
    return {
        "installed":bool(binary),
        "binary":binary,
        "version":version,
        "service_active":service_active,
        "config_path":config,
        "config_error":error,
        "inbounds":inbounds,
    }

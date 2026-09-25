import ipaddress
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

XRAY_BIN_CANDIDATES=["/usr/local/bin/xray","/usr/bin/xray"]
XRAY_CONFIG_CANDIDATES=["/usr/local/etc/xray/config.json","/etc/xray/config.json"]
WG_DIR=Path("/etc/wireguard")
OVPN_DIR=Path("/etc/openvpn")
OVPN_EASYRSA=OVPN_DIR/"easy-rsa"

class ProtocolError(RuntimeError):
    pass

def _run(args, input_text=None, timeout=60):
    try:
        p=subprocess.run(args,input=input_text,text=True,capture_output=True,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise ProtocolError(str(exc)) from exc
    if p.returncode!=0:
        raise ProtocolError((p.stderr or p.stdout or "operation failed").strip()[:1200])
    return p.stdout.strip()

def _active(service):
    if not shutil.which("systemctl"):
        return False
    p=subprocess.run(["systemctl","is-active",service],text=True,capture_output=True)
    return p.returncode==0

def _installed(binary):
    return bool(shutil.which(binary))

def _binary():
    for p in XRAY_BIN_CANDIDATES:
        if os.path.isfile(p) and os.access(p,os.X_OK):
            return p
    return shutil.which("xray")

def _config_path():
    for p in XRAY_CONFIG_CANDIDATES:
        if os.path.isfile(p):
            return p
    return None

def xray_status():
    binary=_binary()
    config=_config_path()
    version=None
    if binary:
        try:
            p=subprocess.run([binary,"version"],text=True,capture_output=True,timeout=5,check=False)
            version=(p.stdout or p.stderr).splitlines()[0][:160] if (p.stdout or p.stderr) else None
        except Exception:
            pass
    inbounds=[]
    error=None
    if config:
        try:
            with open(config,"r",encoding="utf-8") as fh:
                data=json.load(fh)
            for item in data.get("inbounds",[]) if isinstance(data,dict) else []:
                if not isinstance(item,dict):
                    continue
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
        "service_active":_active("xray"),
        "config_path":config,
        "config_error":error,
        "inbounds":inbounds,
    }

def wireguard_status():
    installed=_installed("wg")
    interfaces=[]
    peers=0
    if installed:
        try:
            out=_run(["wg","show","interfaces"],timeout=5)
            interfaces=[x for x in out.split() if x]
            for iface in interfaces:
                dump=_run(["wg","show",iface,"dump"],timeout=5)
                lines=[x for x in dump.splitlines() if x.strip()]
                peers+=max(0,len(lines)-1)
        except Exception:
            pass
    return {
        "installed":installed,
        "service_active":_active("wg-quick@wg0"),
        "interfaces":interfaces,
        "peers":peers,
        "config":str(WG_DIR/"wg0.conf") if (WG_DIR/"wg0.conf").exists() else None,
    }

def openvpn_status():
    installed=_installed("openvpn")
    configs=[]
    server_dir=OVPN_DIR/"server"
    if server_dir.exists():
        configs=[p.stem for p in server_dir.glob("*.conf")]
    active=any(_active(f"openvpn-server@{name}") for name in configs)
    return {
        "installed":installed,
        "service_active":active,
        "servers":configs,
        "config":str(server_dir/"server.conf") if (server_dir/"server.conf").exists() else None,
    }

def stunnel_status():
    return {
        "installed":_installed("stunnel4"),
        "service_active":_active("stunnel4"),
    }

def ssh_status():
    return {
        "installed":_installed("sshd") or _installed("ssh"),
        "service_active":_active("ssh") or _active("sshd"),
    }

def catalog():
    x=xray_status()
    wg=wireguard_status()
    ovpn=openvpn_status()
    st=stunnel_status()
    ssh=ssh_status()
    return {
        "xray":x,
        "wireguard":wg,
        "openvpn":ovpn,
        "stunnel":st,
        "ssh":ssh,
        "capabilities":[
            {"id":"vless","engine":"xray","available":x["installed"]},
            {"id":"vmess","engine":"xray","available":x["installed"]},
            {"id":"trojan","engine":"xray","available":x["installed"]},
            {"id":"shadowsocks","engine":"xray","available":x["installed"]},
            {"id":"wireguard","engine":"wireguard","available":wg["installed"]},
            {"id":"openvpn","engine":"openvpn","available":ovpn["installed"]},
            {"id":"ssh","engine":"openssh","available":ssh["installed"]},
            {"id":"stunnel","engine":"stunnel","available":st["installed"]},
        ]
    }

def install_component(component):
    packages={
        "wireguard":["wireguard","iptables"],
        "openvpn":["openvpn","easy-rsa","iptables"],
        "stunnel":["stunnel4"],
    }
    if component not in packages:
        raise ProtocolError("automatic installation is not available for this component")
    _run(["apt-get","update"],timeout=180)
    _run(["apt-get","install","-y",*packages[component]],timeout=300)
    return catalog().get(component)

def _default_iface():
    out=_run(["ip","-4","route","show","default"],timeout=8)
    m=re.search(r"\bdev\s+(\S+)",out)
    if not m:
        raise ProtocolError("unable to detect default network interface")
    return m.group(1)

def _validate_port(port):
    port=int(port)
    if port<1 or port>65535:
        raise ProtocolError("invalid port")
    return port

def bootstrap_wireguard(port=51820, cidr="10.66.66.1/24", iface="wg0"):
    if not re.fullmatch(r"wg\d{1,2}",iface):
        raise ProtocolError("invalid WireGuard interface name")
    _validate_port(port)
    try:
        net=ipaddress.ip_interface(cidr)
    except Exception as exc:
        raise ProtocolError("invalid WireGuard CIDR") from exc
    if net.version!=4:
        raise ProtocolError("only IPv4 WireGuard bootstrap is supported in this release")
    if not _installed("wg"):
        install_component("wireguard")
    WG_DIR.mkdir(mode=0o700,parents=True,exist_ok=True)
    conf=WG_DIR/f"{iface}.conf"
    if conf.exists():
        raise ProtocolError(f"{conf} already exists")
    private=_run(["wg","genkey"])
    public=_run(["wg","pubkey"],input_text=private+"\n")
    uplink=_default_iface()
    conf.write_text(
        "[Interface]\n"
        f"Address = {net}\n"
        f"ListenPort = {int(port)}\n"
        f"PrivateKey = {private}\n"
        f"PostUp = iptables -A FORWARD -i {iface} -j ACCEPT; iptables -A FORWARD -o {iface} -j ACCEPT; iptables -t nat -A POSTROUTING -o {uplink} -j MASQUERADE\n"
        f"PostDown = iptables -D FORWARD -i {iface} -j ACCEPT; iptables -D FORWARD -o {iface} -j ACCEPT; iptables -t nat -D POSTROUTING -o {uplink} -j MASQUERADE\n",
        encoding="utf-8"
    )
    os.chmod(conf,0o600)
    Path("/etc/sysctl.d/99-makia-wireguard.conf").write_text("net.ipv4.ip_forward=1\n",encoding="utf-8")
    _run(["sysctl","--system"],timeout=30)
    _run(["systemctl","enable","--now",f"wg-quick@{iface}"],timeout=30)
    return {"interface":iface,"address":str(net),"port":int(port),"public_key":public}

def _wg_used_ips(iface):
    used=set()
    conf=WG_DIR/f"{iface}.conf"
    if conf.exists():
        text=conf.read_text(encoding="utf-8",errors="ignore")
        for m in re.finditer(r"AllowedIPs\s*=\s*([^\n#]+)",text):
            for item in m.group(1).split(","):
                item=item.strip()
                try:
                    used.add(str(ipaddress.ip_interface(item).ip))
                except Exception:
                    pass
    return used

def create_wireguard_peer(name, endpoint, iface="wg0", dns="1.1.1.1"):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,48}",name or ""):
        raise ProtocolError("invalid peer name")
    if not re.fullmatch(r"[A-Za-z0-9.:[\]-]{1,255}",endpoint or ""):
        raise ProtocolError("invalid endpoint")
    conf=WG_DIR/f"{iface}.conf"
    if not conf.exists():
        raise ProtocolError("WireGuard server is not bootstrapped")
    text=conf.read_text(encoding="utf-8",errors="ignore")
    m=re.search(r"Address\s*=\s*([^\n]+)",text)
    p=re.search(r"ListenPort\s*=\s*(\d+)",text)
    if not m or not p:
        raise ProtocolError("invalid WireGuard server config")
    server_if=ipaddress.ip_interface(m.group(1).strip())
    network=server_if.network
    used=_wg_used_ips(iface)|{str(server_if.ip)}
    client_ip=None
    for host in network.hosts():
        if str(host) not in used:
            client_ip=host
            break
    if client_ip is None:
        raise ProtocolError("WireGuard address pool exhausted")
    client_private=_run(["wg","genkey"])
    client_public=_run(["wg","pubkey"],input_text=client_private+"\n")
    server_public=_run(["wg","show",iface,"public-key"])
    _run(["wg","set",iface,"peer",client_public,"allowed-ips",f"{client_ip}/32"])
    with conf.open("a",encoding="utf-8") as fh:
        fh.write(f"\n# Makia peer: {name}\n[Peer]\nPublicKey = {client_public}\nAllowedIPs = {client_ip}/32\n")
    os.chmod(conf,0o600)
    client=(
        "[Interface]\n"
        f"PrivateKey = {client_private}\n"
        f"Address = {client_ip}/32\n"
        f"DNS = {dns}\n\n"
        "[Peer]\n"
        f"PublicKey = {server_public}\n"
        f"Endpoint = {endpoint}:{p.group(1)}\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        "PersistentKeepalive = 25\n"
    )
    return {"name":name,"address":str(client_ip),"public_key":client_public,"config":client}

def bootstrap_openvpn(port=1194, proto="udp"):
    port=_validate_port(port)
    if proto not in {"udp","tcp"}:
        raise ProtocolError("invalid OpenVPN protocol")
    if not _installed("openvpn"):
        install_component("openvpn")
    if not OVPN_EASYRSA.exists():
        shutil.copytree("/usr/share/easy-rsa",OVPN_EASYRSA)
    server_dir=OVPN_DIR/"server"
    server_dir.mkdir(parents=True,exist_ok=True)
    pki=OVPN_EASYRSA/"pki"
    env=os.environ.copy()
    env["EASYRSA_BATCH"]="1"
    def er(args,timeout=180):
        try:
            p=subprocess.run([str(OVPN_EASYRSA/"easyrsa"),*args],cwd=str(OVPN_EASYRSA),env=env,text=True,capture_output=True,timeout=timeout,check=False)
        except Exception as exc:
            raise ProtocolError(str(exc)) from exc
        if p.returncode!=0:
            raise ProtocolError((p.stderr or p.stdout or "easy-rsa failed").strip()[:1200])
    if not pki.exists():
        er(["init-pki"])
    if not (pki/"ca.crt").exists():
        er(["build-ca","nopass"])
    if not (pki/"issued/server.crt").exists():
        er(["build-server-full","server","nopass"])
    if not (pki/"dh.pem").exists():
        er(["gen-dh"],timeout=300)
    er(["gen-crl"])
    ta=server_dir/"ta.key"
    if not ta.exists():
        _run(["openvpn","--genkey","secret",str(ta)])
    for src,dst in [
        (pki/"ca.crt",server_dir/"ca.crt"),
        (pki/"issued/server.crt",server_dir/"server.crt"),
        (pki/"private/server.key",server_dir/"server.key"),
        (pki/"dh.pem",server_dir/"dh.pem"),
        (pki/"crl.pem",server_dir/"crl.pem"),
    ]:
        shutil.copy2(src,dst)
    uplink=_default_iface()
    up=OVPN_DIR/"makia-up.sh"
    down=OVPN_DIR/"makia-down.sh"
    up.write_text(f"#!/bin/sh\niptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o {uplink} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o {uplink} -j MASQUERADE\n",encoding="utf-8")
    down.write_text(f"#!/bin/sh\niptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o {uplink} -j MASQUERADE 2>/dev/null || true\n",encoding="utf-8")
    os.chmod(up,0o700); os.chmod(down,0o700)
    server_conf=server_dir/"server.conf"
    server_conf.write_text(
        f"port {port}\nproto {proto}\ndev tun\n"
        "topology subnet\nserver 10.8.0.0 255.255.255.0\n"
        "ca ca.crt\ncert server.crt\nkey server.key\ndh dh.pem\ncrl-verify crl.pem\n"
        "tls-crypt ta.key\n"
        "push \"redirect-gateway def1 bypass-dhcp\"\n"
        "push \"dhcp-option DNS 1.1.1.1\"\npush \"dhcp-option DNS 8.8.8.8\"\n"
        "keepalive 10 120\npersist-key\npersist-tun\nuser nobody\ngroup nogroup\n"
        "cipher AES-256-GCM\nauth SHA256\nverb 3\n"
        f"script-security 2\nup {up}\ndown {down}\n",
        encoding="utf-8"
    )
    Path("/etc/sysctl.d/99-makia-openvpn.conf").write_text("net.ipv4.ip_forward=1\n",encoding="utf-8")
    _run(["sysctl","--system"],timeout=30)
    _run(["systemctl","enable","--now","openvpn-server@server"],timeout=30)
    return {"server":"server","port":port,"proto":proto}

def create_openvpn_client(name, endpoint, port=1194, proto="udp"):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,48}",name or ""):
        raise ProtocolError("invalid client name")
    if not re.fullmatch(r"[A-Za-z0-9.:[\]-]{1,255}",endpoint or ""):
        raise ProtocolError("invalid endpoint")
    port=_validate_port(port)
    if proto not in {"udp","tcp"}:
        raise ProtocolError("invalid OpenVPN protocol")
    if not (OVPN_EASYRSA/"pki/ca.crt").exists():
        raise ProtocolError("OpenVPN server is not bootstrapped")
    env=os.environ.copy(); env["EASYRSA_BATCH"]="1"
    p=subprocess.run([str(OVPN_EASYRSA/"easyrsa"),"build-client-full",name,"nopass"],cwd=str(OVPN_EASYRSA),env=env,text=True,capture_output=True,timeout=180,check=False)
    if p.returncode!=0:
        raise ProtocolError((p.stderr or p.stdout or "easy-rsa failed").strip()[:1200])
    pki=OVPN_EASYRSA/"pki"
    ca=(pki/"ca.crt").read_text(encoding="utf-8")
    cert=(pki/f"issued/{name}.crt").read_text(encoding="utf-8")
    key=(pki/f"private/{name}.key").read_text(encoding="utf-8")
    ta=(OVPN_DIR/"server/ta.key").read_text(encoding="utf-8")
    transport="udp" if proto=="udp" else "tcp-client"
    client=(
        "client\ndev tun\n"
        f"proto {transport}\nremote {endpoint} {port}\n"
        "resolv-retry infinite\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\n"
        "cipher AES-256-GCM\nauth SHA256\nverb 3\nkey-direction 1\n"
        f"<ca>\n{ca}</ca>\n<cert>\n{cert}</cert>\n<key>\n{key}</key>\n<tls-crypt>\n{ta}</tls-crypt>\n"
    )
    return {"name":name,"config":client}

def status():
    return xray_status()

import datetime as dt
import json
import os
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import protocol_ops


def make_test_certificate(root:Path):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"test.example.com")])
    now=dt.datetime.now(dt.timezone.utc)
    cert=(
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now-dt.timedelta(minutes=1))
        .not_valid_after(now+dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("test.example.com")]),critical=False)
        .sign(key,hashes.SHA256())
    )
    cert_path=root/"cert.pem"
    key_path=root/"key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()))
    return cert_path,key_path


def main():
    binary=os.environ["XRAY_BIN"]
    version=protocol_ops._run([binary,"version"],timeout=10).splitlines()[0]
    print(version)
    assert "26.3.27" in version

    root=Path("/tmp/makia-xray-matrix")
    root.mkdir(parents=True,exist_ok=True)
    cert_path,key_path=make_test_certificate(root)
    original_tls=protocol_ops._xray_materialize_tls
    protocol_ops._xray_materialize_tls=lambda domain:(cert_path,key_path)
    try:
        data=protocol_ops._ensure_xray_stats(
            protocol_ops._xray_default_config(Path("/tmp/makia-xray-config.json"))
        )

        # VLESS + XHTTP + REALITY
        reality_stream,reality_meta=protocol_ops._build_xray_stream(
            binary,"vless","xhttp","reality","/makia","www.microsoft.com","www.microsoft.com:443",
        )
        data["inbounds"].append({
            "tag":"makia-ci-vless","listen":"127.0.0.1","port":21001,"protocol":"vless",
            "settings":{"clients":[{"id":str(uuid.uuid4()),"email":"ci-vless","level":0}],"decryption":"none"},
            "streamSettings":reality_stream,
            "sniffing":{"enabled":True,"destOverride":["http","tls","quic"],"routeOnly":True},
        })

        # VMess + WebSocket
        vmess_stream,_=protocol_ops._build_xray_stream(binary,"vmess","ws","none","/vmess","","")
        data["inbounds"].append({
            "tag":"makia-ci-vmess","listen":"127.0.0.1","port":21002,"protocol":"vmess",
            "settings":{"clients":[{"id":str(uuid.uuid4()),"email":"ci-vmess","level":0}]},
            "streamSettings":vmess_stream,
        })

        # Trojan + TLS using a real generated certificate.
        trojan_stream,_=protocol_ops._build_xray_stream(binary,"trojan","tcp","tls","/","test.example.com","")
        data["inbounds"].append({
            "tag":"makia-ci-trojan","listen":"127.0.0.1","port":21003,"protocol":"trojan",
            "settings":{"clients":[{"password":"ci-trojan-secret","email":"ci-trojan","level":0}]},
            "streamSettings":trojan_stream,
        })

        # Shadowsocks
        ss_stream,_=protocol_ops._build_xray_stream(binary,"shadowsocks","tcp","none","/","","")
        data["inbounds"].append({
            "tag":"makia-ci-ss","listen":"127.0.0.1","port":21004,"protocol":"shadowsocks",
            "settings":{"method":"aes-128-gcm","password":"ci-shadow-secret","network":"tcp,udp"},
            "streamSettings":ss_stream,
        })

        # Hysteria2 + TLS
        data["inbounds"].append({
            "tag":"makia-ci-hysteria2","listen":"127.0.0.1","port":21005,"protocol":"hysteria",
            "settings":{"version":2,"users":[{"auth":"ci-hy2-secret","email":"ci-hy2","level":0}]},
            "streamSettings":{
                "method":"hysteria","security":"tls",
                "hysteriaSettings":{"version":2},
                "tlsSettings":{
                    "serverName":"test.example.com","alpn":["h3"],
                    "certificates":[{"certificateFile":str(cert_path),"keyFile":str(key_path)}],
                },
            },
        })

        # HTTP proxy.
        data["inbounds"].append({
            "tag":"makia-ci-http","listen":"127.0.0.1","port":21006,"protocol":"http",
            "settings":{"accounts":[{"user":"ci-http","pass":"ci-http-secret"}]},
            "streamSettings":{"method":"raw","security":"none"},
        })

        # SOCKS5 proxy.
        data["inbounds"].append({
            "tag":"makia-ci-socks","listen":"127.0.0.1","port":21007,"protocol":"socks",
            "settings":{"auth":"password","accounts":[{"user":"ci-socks","pass":"ci-socks-secret"}],"udp":True,"ip":"127.0.0.1"},
            "streamSettings":{"method":"raw","security":"none"},
        })

        target=protocol_ops._xray_temp_json_path(Path("/tmp/config.json"),"runtime-matrix")
        target.write_text(json.dumps(data,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        try:
            protocol_ops._xray_test_config(binary,target)
        finally:
            target.unlink(missing_ok=True)

        assert reality_meta["public_key"]
        assert reality_meta["short_id"]
        print("Xray 26.3.27 guided protocol matrix PASS: VLESS, VMess, Trojan, Shadowsocks, Hysteria2, HTTP, SOCKS5")
    finally:
        protocol_ops._xray_materialize_tls=original_tls


if __name__=="__main__":
    main()

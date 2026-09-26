import json
import os
import uuid
from pathlib import Path

from app import protocol_ops


def main():
    binary=os.environ["XRAY_BIN"]
    version=protocol_ops._run([binary,"version"],timeout=10).splitlines()[0]
    print(version)

    data=protocol_ops._ensure_xray_stats(
        protocol_ops._xray_default_config(Path("/tmp/makia-xray-config.json"))
    )
    stream,meta=protocol_ops._build_xray_stream(
        binary,
        "vless",
        "xhttp",
        "reality",
        "/makia",
        "www.microsoft.com",
        "www.microsoft.com:443",
    )
    client_id=str(uuid.uuid4())
    data["inbounds"].append({
        "tag":"makia-ci-vless-2087",
        "listen":"127.0.0.1",
        "port":2087,
        "protocol":"vless",
        "settings":{
            "clients":[{"id":client_id,"email":"ci-user","level":0}],
            "decryption":"none",
        },
        "streamSettings":stream,
        "sniffing":{"enabled":True,"destOverride":["http","tls","quic"],"routeOnly":True},
    })

    trojan_stream,trojan_meta=protocol_ops._build_xray_stream(
        binary,
        "trojan",
        "xhttp",
        "reality",
        "/trojan",
        "www.microsoft.com",
        "www.microsoft.com:443",
    )
    data["inbounds"].append({
        "tag":"makia-ci-trojan-2088",
        "listen":"127.0.0.1",
        "port":2088,
        "protocol":"trojan",
        "settings":{
            "clients":[{"password":"ci-trojan-secret","email":"ci-trojan","level":0}],
        },
        "streamSettings":trojan_stream,
        "sniffing":{"enabled":True,"destOverride":["http","tls","quic"],"routeOnly":True},
    })

    target=protocol_ops._xray_temp_json_path(Path("/tmp/config.json"),"runtime-smoke")
    target.write_text(json.dumps(data,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    try:
        protocol_ops._xray_test_config(binary,target)
    finally:
        target.unlink(missing_ok=True)

    assert meta["public_key"]
    assert meta["short_id"]
    assert trojan_meta["public_key"]
    assert trojan_meta["short_id"]
    print("Xray 26.3.27 VLESS + Trojan REALITY config smoke PASS")


if __name__=="__main__":
    main()

from app import protocol_ops

def test_catalog_exposes_http_and_socks_as_guided(monkeypatch):
    monkeypatch.setattr(protocol_ops, "xray_status", lambda: {
        "installed": True, "binary":"/usr/bin/xray", "version":"test",
        "service_active":True, "config_path":"/tmp/config.json",
        "config_error":None, "inbounds":[]
    })
    monkeypatch.setattr(protocol_ops, "wireguard_status", lambda: {"installed":False,"service_active":False,"interfaces":[],"peers":0,"config":None})
    monkeypatch.setattr(protocol_ops, "openvpn_status", lambda: {"installed":False,"service_active":False,"servers":[],"config":None})
    monkeypatch.setattr(protocol_ops, "stunnel_status", lambda: {"installed":False,"service_active":False})
    monkeypatch.setattr(protocol_ops, "ssh_status", lambda: {"installed":True,"service_active":True})
    caps={item["id"]:item for item in protocol_ops.catalog()["capabilities"]}
    assert caps["http"]["available"] is True
    assert caps["http"]["mode"] == "guided"
    assert caps["socks"]["available"] is True
    assert caps["socks"]["mode"] == "guided"

    assert caps["tunnel"]["available"] is True
    assert caps["tunnel"]["mode"] == "guided"

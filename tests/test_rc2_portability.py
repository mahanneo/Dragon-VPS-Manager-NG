import io
from pathlib import Path

import pytest

from app import protocol_ops, system_ops


def test_wireguard_mtu_and_keepalive_validation():
    assert protocol_ops._validate_wireguard_mtu(0)==0
    assert protocol_ops._validate_wireguard_mtu(1280)==1280
    assert protocol_ops._validate_keepalive(25)==25
    assert protocol_ops._validate_keepalive(0)==0
    with pytest.raises(protocol_ops.ProtocolError):
        protocol_ops._validate_wireguard_mtu(1199)
    with pytest.raises(protocol_ops.ProtocolError):
        protocol_ops._validate_wireguard_mtu(1501)
    with pytest.raises(protocol_ops.ProtocolError):
        protocol_ops._validate_keepalive(3601)


def test_wireguard_peer_config_uses_domain_mtu_keepalive(tmp_path,monkeypatch):
    wg_dir=tmp_path/"wireguard"
    wg_dir.mkdir()
    (wg_dir/"wg0.conf").write_text(
        "[Interface]\nAddress = 10.66.66.1/24\nListenPort = 443\nPrivateKey = server-private\nMTU = 1280\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(protocol_ops,"WG_DIR",wg_dir)

    def fake_run(args,input_text=None,timeout=60):
        if args[:2]==["wg","genkey"]:
            return "client-private"
        if args[:2]==["wg","pubkey"]:
            return "client-public"
        if args[:3]==["wg","show","wg0"] and args[3:] == ["public-key"]:
            return "server-public"
        if args[:3]==["wg","set","wg0"]:
            return ""
        raise AssertionError(f"unexpected command: {args}")

    monkeypatch.setattr(protocol_ops,"_run",fake_run)
    result=protocol_ops.create_wireguard_peer(
        "phone01","vpn.example.com",dns="1.1.1.1",mtu=1280,persistent_keepalive=25
    )
    config=result["config"]
    assert "Endpoint = vpn.example.com:443" in config
    assert "MTU = 1280" in config
    assert "PersistentKeepalive = 25" in config
    assert result["port"]==443


def test_xray_guided_capabilities_are_explicit():
    caps=protocol_ops.xray_guided_capabilities()
    assert caps["advanced_json"] is True
    assert "vless" in caps["protocols"]
    assert "trojan" in caps["reality_guided_protocols"]
    assert set(caps["reality_transports"])=={"tcp","grpc","xhttp"}


def test_trojan_reality_stream_supported_in_guided_builder(monkeypatch):
    monkeypatch.setattr(protocol_ops,"_x25519_pair",lambda binary:("private-key","public-key"))
    stream,meta=protocol_ops._build_xray_stream(
        "/tmp/xray","trojan","xhttp","reality","/makia",
        "www.microsoft.com","www.microsoft.com:443",
    )
    assert stream["method"]=="xhttp"
    assert stream["security"]=="reality"
    assert stream["realitySettings"]["target"]=="www.microsoft.com:443"
    assert meta["public_key"]=="public-key"


def test_portable_backup_roundtrip(tmp_path):
    data=tmp_path/"data"
    data.mkdir()
    (data/".secret").write_bytes(b"secret-material")
    (data/"makia.db").write_bytes(b"sqlite-placeholder")
    wg=tmp_path/"wg0.conf"
    wg.write_text("[Interface]\nPrivateKey = server-key\n",encoding="utf-8")

    result=system_ops.create_portable_backup(
        str(data),"StrongBackupPass123",
        metadata={"panel_domain":"vpn.example.com","version":"0.12.0-rc2"},
        sources=[(data,"data"),(wg,"host/etc/wireguard/wg0.conf")],
    )
    assert result["size"]>100
    verified=system_ops.verify_portable_backup(result["blob"],"StrongBackupPass123")
    assert verified["ok"] is True
    assert verified["manifest"]["metadata"]["panel_domain"]=="vpn.example.com"
    assert any(name.endswith("data/.secret") for name in verified["members"])
    assert any(name.endswith("host/etc/wireguard/wg0.conf") for name in verified["members"])


def test_portable_backup_wrong_password_rejected(tmp_path):
    data=tmp_path/"data"
    data.mkdir()
    (data/"makia.db").write_bytes(b"db")
    result=system_ops.create_portable_backup(
        str(data),"StrongBackupPass123",sources=[(data,"data")]
    )
    with pytest.raises(system_ops.OperationError):
        system_ops.verify_portable_backup(result["blob"],"WrongPassword123")

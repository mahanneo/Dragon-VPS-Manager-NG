import base64
import json
import time

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app import main as main_app
from app import security


def _request(path="/api/test"):
    return Request({
        "type":"http","method":"GET","path":path,"headers":[],
        "query_string":b"","scheme":"http",
        "server":("127.0.0.1",8787),"client":("127.0.0.1",1234),
    })


def test_short_configurable_session_ttl(monkeypatch):
    monkeypatch.setattr(security,"ensure_secret",lambda:b"s"*48)
    token=security.make_session("admin",300)
    raw=token.split(".",1)[0]
    payload=json.loads(base64.urlsafe_b64decode(raw+"="*(-len(raw)%4)).decode())
    remaining=payload["exp"]-int(time.time())
    assert 295 <= remaining <= 300


def test_public_origin_preserves_non_default_port(monkeypatch):
    monkeypatch.setattr(main_app,"get_setting",lambda key,default=None: default)
    assert main_app.public_origin(_request())=="http://127.0.0.1:8787"


def test_share_response_is_no_store(monkeypatch):
    payload={
        "share_type":"xray",
        "share_text":"vless://abc@example.test:443",
        "primary_text":"vless://abc@example.test:443",
        "summary":{"subscription_url":"http://127.0.0.1:8787/sub/abc?format=base64"},
        "files":{},
    }
    monkeypatch.setattr(main_app,"require_user",lambda request:"admin")
    monkeypatch.setattr(main_app,"_resolve_access_payload",lambda kind,key,request:(payload,{"id":1}))
    monkeypatch.setattr(main_app,"get_protocol_client",lambda client_id:{"subscription_id":"abc"})
    monkeypatch.setattr(main_app,"get_setting",lambda key,default=None: default)
    response=main_app.access_share("xray","1",_request("/api/access/xray/1/share"))
    assert response.status_code==200
    assert response.headers["cache-control"]=="no-store, private"
    body=json.loads(response.body)
    assert body["share_text"].startswith("vless://")
    assert body["qr"].startswith("data:image/svg+xml;base64,")
    assert body["subscription_qr"].startswith("data:image/svg+xml;base64,")


def test_ssh_share_respects_disabled_npv(monkeypatch):
    monkeypatch.setattr(main_app,"require_user",lambda request:"admin")
    monkeypatch.setattr(main_app,"operator_settings_snapshot",lambda:{
        "delivery":{"npv_enabled":False}
    })
    with pytest.raises(HTTPException) as exc:
        main_app.access_share("ssh","user001",_request("/api/access/ssh/user001/share"))
    assert exc.value.status_code==409


def test_operator_settings_persist_and_validate(monkeypatch):
    store={}
    monkeypatch.setattr(main_app,"require_mutation",lambda request:"admin")
    monkeypatch.setattr(main_app,"set_setting",lambda key,value:store.__setitem__(str(key),str(value)))
    monkeypatch.setattr(main_app,"get_setting",lambda key,default=None:store.get(str(key),default))
    monkeypatch.setattr(main_app,"audit",lambda *args,**kwargs:None)
    payload=main_app.OperatorSettings(
        session_max_age_minutes=180,
        profile_prefix="Makia Test",
        npv_enabled=True,
        npv_dns_mode="UDP",
        npv_udpgw_port=7300,
        npv_transparent_dns=False,
        show_qr=True,
        ssh_password_mode="pin6",
        ssh_expire_days=30,
        ssh_sessions=2,
        ssh_devices=1,
        xray_protocol="vless",
        xray_port=2087,
        xray_transport="xhttp",
        xray_security="reality",
        xray_path="/makia",
        xray_sni="www.microsoft.com",
        xray_reality_target="www.microsoft.com:443",
        xray_quota_gb=50,
        xray_expire_days=30,
        xray_ip_limit=1,
        xray_reset_days=30,
        wireguard_dns="1.1.1.1",
        openvpn_port=1194,
        openvpn_proto="udp",
    )
    result=main_app.operator_settings_put(payload,_request("/api/settings/operator"))
    assert result["session_max_age_minutes"]==180
    assert result["delivery"]["profile_prefix"]=="Makia Test"
    assert result["defaults"]["ssh_sessions"]==2
    assert result["defaults"]["xray_transport"]=="xhttp"

import pytest
from fastapi import HTTPException

from app import main as main_app


def test_premium_feature_gate_denies_community(monkeypatch):
    monkeypatch.setattr(main_app,"license_snapshot",lambda:{
        "valid":False,"tier":"community","installation_id":"MK-TEST","features":["ssh","security","domain","updates","support"]
    })
    with pytest.raises(HTTPException) as exc:
        main_app.assert_license_feature("xray")
    assert exc.value.status_code==403
    assert exc.value.detail["code"]=="license_required"
    assert exc.value.detail["installation_id"]=="MK-TEST"


def test_premium_feature_gate_allows_signed_feature(monkeypatch):
    monkeypatch.setattr(main_app,"license_snapshot",lambda:{
        "valid":True,"tier":"full","installation_id":"MK-TEST","features":["ssh","xray","openvpn"]
    })
    main_app.assert_license_feature("xray")
    main_app.assert_license_feature("openvpn")


def test_support_snapshot_never_exposes_private_signing_material(monkeypatch):
    monkeypatch.setenv("MAKIA_SUPPORT_TELEGRAM","@MakiaSupport")
    monkeypatch.setenv("MAKIA_SUPPORT_WEBHOOK_URL","https://support.example.test/tickets")
    state=main_app.support_snapshot()
    assert state["telegram_username"]=="MakiaSupport"
    assert state["telegram_url"]=="https://t.me/MakiaSupport"
    assert state["webhook_enabled"] is True
    assert "token" not in state
    assert "key" not in state

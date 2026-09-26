import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pyzipper
from playwright.sync_api import sync_playwright

DATA=Path(os.environ["MAKIA_DATA_DIR"])
BASE_URL="http://127.0.0.1:8787"
PASSWORD=os.environ["MAKIA_INITIAL_ADMIN_PASSWORD"]


def seed():
    shutil.rmtree(DATA,ignore_errors=True)
    DATA.mkdir(parents=True,exist_ok=True)
    from app.db import init_db, create_protocol_client, upsert_access_artifact, get_protocol_client
    from app import access_ops

    init_db()
    client_id=create_protocol_client(
        "browser-client","xray","vless","browser-inbound","browser-credential",
        "vless://browser-credential@example.test:443?type=tcp&security=none#browser-client",
        0,0,1,0,
    )
    payload=access_ops.xray_payload(
        "browser-client","vless",
        "vless://browser-credential@example.test:443?type=tcp&security=none#browser-client",
        f"{BASE_URL}/sub/browser?format=base64",
        f"{BASE_URL}/client/browser",
    )
    upsert_access_artifact(
        "xray",str(client_id),"browser-client","vless",payload["native_filename"],
        access_ops.seal_payload(payload),"{}",
    )
    return client_id,get_protocol_client(client_id)["subscription_id"]


def wait_server(timeout=20):
    deadline=time.time()+timeout
    while time.time()<deadline:
        try:
            with urllib.request.urlopen(BASE_URL+"/healthz",timeout=1) as r:
                if r.status==200:
                    return
        except Exception:
            time.sleep(.25)
    raise RuntimeError("test server did not become healthy")


def main():
    client_id,subscription_id=seed()
    env=os.environ.copy()
    proc=subprocess.Popen(
        [sys.executable,"-m","uvicorn","app.main:app","--host","127.0.0.1","--port","8787"],
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,env=env,
    )
    try:
        wait_server()
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True)
            portal=browser.new_page()
            portal.goto(BASE_URL+"/client/"+subscription_id,wait_until="networkidle")
            assert portal.locator(".client-qr-card").count()==2
            assert portal.locator('img[alt="Profile QR"]').count()==1
            assert portal.locator('img[alt="Subscription QR"]').count()==1
            portal.close()

            page=browser.new_page(accept_downloads=True)
            page_errors=[]
            page.on("pageerror",lambda exc: page_errors.append(str(exc)))
            page.goto(BASE_URL+"/login",wait_until="networkidle")
            page.locator('input[name="username"]').fill("admin")
            page.locator('input[name="password"]').fill(PASSWORD)
            page.locator('button[type="submit"]').click()
            page.wait_for_url(BASE_URL+"/")

            page.locator('button[data-view="access"]').click()
            page.locator(".access-profile",has_text="browser-client").wait_for()

            row=page.locator(".access-profile",has_text="browser-client")
            row.locator('[data-action="access-share"]').click()
            page.locator(".share-modal").wait_for()
            assert page.locator(".share-qr").count() >= 1
            assert page.locator("#shareText").input_value().startswith("vless://")
            assert page.locator("#shareSubscription").input_value().startswith(BASE_URL+"/sub/")
            details=page.locator(".xray-share-details").inner_text()
            assert "VLESS" in details.upper()
            assert "example.test" in details
            assert "443" in details
            with page.expect_download() as qr_download:
                page.locator('[data-action="qr-download"]').click()
            qr_path=Path("/tmp/makia-browser-xray-qr.svg")
            qr_download.value.save_as(str(qr_path))
            assert "<svg" in qr_path.read_text(encoding="utf-8")
            with page.expect_download() as sub_qr_download:
                page.locator('[data-action="subscription-qr-download"]').click()
            sub_qr_path=Path("/tmp/makia-browser-xray-subscription-qr.svg")
            sub_qr_download.value.save_as(str(sub_qr_path))
            assert "<svg" in sub_qr_path.read_text(encoding="utf-8")
            page.locator('.close-btn[data-action="modal-close"]').click()

            row=page.locator(".access-profile",has_text="browser-client")
            row.locator('[data-action="protected-export"]').click()
            page.locator("#protectedPassword").wait_for()
            page.locator("#protectedPassword").fill("739251")
            with page.expect_download() as dl:
                page.locator('[data-action="protected-download-confirm"]').click()
            zip_path=Path("/tmp/makia-browser-protected.zip")
            dl.value.save_as(str(zip_path))
            assert zip_path.stat().st_size>100
            with pyzipper.AESZipFile(zip_path,"r") as zf:
                zf.setpassword(b"739251")
                names=zf.namelist()
                assert any(name.endswith("-profile.json") for name in names)
                assert any(name.endswith("-qr.svg") for name in names)
                assert any(name.endswith("-subscription.txt") for name in names)
                assert any(name.endswith("-subscription-qr.svg") for name in names)

            page.locator('.close-btn[data-action="modal-close"]').click()
            row=page.locator(".access-profile",has_text="browser-client")
            with page.expect_download() as native:
                row.locator('[data-action="native-export"]').click()
            native_path=Path("/tmp/makia-browser-native.txt")
            native.value.save_as(str(native_path))
            assert "vless://" in native_path.read_text(encoding="utf-8")

            page.locator('[data-shell-action="create-access"]').click()
            page.locator(".provision-wizard").wait_for()
            assert page.locator(".wizard-protocol").count()==4
            page.locator('.close-btn[data-action="modal-close"]').click()

            page.locator('button[data-view="dashboard"]').click()
            page.locator(".command-hero").wait_for()
            page.locator('[data-action="self-test"]').click()
            page.locator(".diagnostics-modal").wait_for()
            assert page.locator(".diagnostic-score.pass").count()==1
            page.locator('.close-btn[data-action="modal-close"]').click()

            for view in ["sessions","protocols","services","nodes","security","backups","audit","updates","settings"]:
                nav=page.locator(f'aside.sidebar nav button[data-view="{view}"]')
                nav.click()
                page.wait_for_timeout(450)
                assert page.locator("#content").inner_text().strip(), f"{view} rendered empty content"
                assert "active" in (nav.get_attribute("class") or ""), f"{view} sidebar item not active"

            page.locator('[data-action="settings-tab"][data-tab="delivery"]').click()
            page.locator("#opProfilePrefix").wait_for()
            page.locator("#opProfilePrefix").fill("BrowserMakia")
            page.locator('[data-action="settings-operator-save"]').click()
            page.locator("#opProfilePrefix").wait_for()
            assert page.locator("#opProfilePrefix").input_value()=="BrowserMakia"

            page.locator('[data-action="settings-tab"][data-tab="subscription"]').click()
            page.locator("#opSubscriptionFormat").wait_for()
            page.locator("#opSubscriptionFormat").select_option("raw")
            page.locator('[data-action="settings-operator-save"]').click()
            page.locator("#opSubscriptionFormat").wait_for()
            assert page.locator("#opSubscriptionFormat").input_value()=="raw"

            page.locator('[data-action="settings-tab"][data-tab="vpn"]').click()
            page.locator("#opWgPort").wait_for()
            page.locator('[data-action="wg-compat-preset"]').click()
            assert page.locator("#opWgPort").input_value()=="443"
            assert page.locator("#opWgMtu").input_value()=="1280"
            assert page.locator("#opWgKeepalive").input_value()=="15"
            assert page.locator("#opWgAllowedIps").input_value()=="0.0.0.0/0"
            page.locator('[data-action="settings-operator-save"]').click()
            page.locator("#opWgPort").wait_for()
            assert page.locator("#opWgPort").input_value()=="443"

            for tab in ["general","domain","ssh","xray","vpn","delivery","subscription","security","api","recovery"]:
                page.locator(f'[data-action="settings-tab"][data-tab="{tab}"]').click()
                page.wait_for_timeout(180)
                assert page.locator(".settings-content-v2").inner_text().strip(), f"settings tab {tab} empty"

            page.locator('[data-action="settings-tab"][data-tab="recovery"]').click()
            page.locator('[data-action="portable-backup"]').click()
            page.locator("#migrationPassword").fill("MigrationPass!2026")
            with page.expect_download() as portable:
                page.locator('[data-action="portable-backup-download"]').click()
            portable_path=Path("/tmp/makia-browser-portable.zip")
            portable.value.save_as(str(portable_path))
            with pyzipper.AESZipFile(portable_path,"r") as zf:
                zf.setpassword(b"MigrationPass!2026")
                names=zf.namelist()
                assert "manifest.json" in names
                assert "payload/data.tar.gz" in names
                manifest=zf.read("manifest.json").decode("utf-8")
                assert "makia-portable-migration" in manifest
            page.locator('.close-btn[data-action="modal-close"]').click()

            for view in ["dashboard","access"]:
                nav=page.locator(f'aside.sidebar nav button[data-view="{view}"]')
                nav.click()
                page.wait_for_timeout(450)
                assert page.locator("#content").inner_text().strip(), f"{view} rendered empty content"

            assert not page_errors, "JavaScript page errors: "+repr(page_errors)
            browser.close()
        print(f"browser smoke PASS; client_id={client_id}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if proc.returncode not in (0,-15,None):
            print(proc.stdout.read() if proc.stdout else "")


if __name__=="__main__":
    main()

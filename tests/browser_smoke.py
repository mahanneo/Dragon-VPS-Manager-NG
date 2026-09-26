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
    from app.db import init_db, create_protocol_client, upsert_access_artifact
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
    return client_id


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
    client_id=seed()
    env=os.environ.copy()
    proc=subprocess.Popen(
        [sys.executable,"-m","uvicorn","app.main:app","--host","127.0.0.1","--port","8787"],
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,env=env,
    )
    try:
        wait_server()
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True)
            page=browser.new_page(accept_downloads=True)
            page.goto(BASE_URL+"/login",wait_until="networkidle")
            page.locator('input[name="username"]').fill("admin")
            page.locator('input[name="password"]').fill(PASSWORD)
            page.locator('button[type="submit"]').click()
            page.wait_for_url(BASE_URL+"/")

            page.locator('button[data-view="access"]').click()
            page.locator(".access-profile",has_text="browser-client").wait_for()

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

            page.locator('[data-action="modal-close"]').click()
            row=page.locator(".access-profile",has_text="browser-client")
            with page.expect_download() as native:
                row.locator('[data-action="native-export"]').click()
            native_path=Path("/tmp/makia-browser-native.txt")
            native.value.save_as(str(native_path))
            assert "vless://" in native_path.read_text(encoding="utf-8")

            page.locator('[data-shell-action="create-access"]').click()
            page.locator(".provision-wizard").wait_for()
            assert page.locator(".wizard-protocol").count()==4
            page.locator('[data-action="modal-close"]').click()

            page.locator('button[data-view="dashboard"]').click()
            page.locator(".command-hero").wait_for()
            assert page.locator('[data-action="self-test"]').count()==1
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

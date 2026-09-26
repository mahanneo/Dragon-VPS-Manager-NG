from pathlib import Path


ROOT=Path(__file__).resolve().parents[1]
JS=(ROOT/"app/static/app.js").read_text(encoding="utf-8")
SHELL=(ROOT/"app/templates/dashboard.html").read_text(encoding="utf-8")


def test_access_exports_use_delegated_actions():
    assert 'data-action="protected-export"' in JS
    assert 'data-action="native-export"' in JS
    assert 'onclick="downloadProtectedAccess(' not in JS
    assert 'onclick="downloadAccessNative(' not in JS
    assert "async function performProtectedDownload" in JS
    assert "async function downloadAccessNative" in JS


def test_shell_has_no_inline_click_handlers():
    assert "onclick=" not in SHELL
    assert 'data-shell-action="create-access"' in SHELL
    assert 'data-shell-action="command"' in SHELL
    assert 'data-shell-action="refresh"' in SHELL


def test_provisioning_wizard_contract():
    for marker in [
        "SMART PROVISIONING",
        "wizard-protocol",
        "wizard-create",
        "Protected delivery package",
        "protocol-bootstrap",
        "runSelfTest",
    ]:
        assert marker in JS


def test_dashboard_uses_live_operational_sources():
    assert "Promise.all([" in JS
    assert "api('/api/overview')" in JS
    assert "api('/api/access')" in JS
    assert "api('/api/protocols')" in JS
    assert "OPERATIONS COCKPIT" in JS

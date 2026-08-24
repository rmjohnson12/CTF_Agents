import pytest
import json
from pathlib import Path
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

from core.utils.security import SecurityPolicyError
from tools.web.browser_snapshot_tool import BrowserSnapshotTool

# Skip this test cleanly if Playwright isn't installed in some environments.
pytest.importorskip("playwright")

def _chromium_available() -> bool:
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        return True
    except PlaywrightError:
        return False

def test_browser_snapshot_example_com_smoke(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CTF_AGENTS_ALLOWED_NETWORKS", "example.com")
    if not _chromium_available():
        pytest.skip("Playwright Chromium binary is not installed in this environment.")

    tool = BrowserSnapshotTool(results_dir=str(tmp_path))

    res = tool.snapshot("https://example.com", timeout_s=30)

    # Basic metadata
    assert res.final_url.startswith("https://example.com")
    assert "Example Domain" in res.title

    # Artifacts should exist
    assert Path(res.screenshot_path).exists()
    assert Path(res.html_path).exists()
    assert Path(res.json_path).exists()

    # Extracted signals should be the right types
    assert isinstance(res.links, list)
    assert isinstance(res.forms, list)
    assert isinstance(res.text_preview, str)
    assert isinstance(res.html_content, str)

    # And should have some content for this page
    assert len(res.text_preview) > 0
    assert len(res.html_content) > 0

def test_browser_snapshot_with_cookies(tmp_path: Path, mocker, monkeypatch):
    monkeypatch.setenv("CTF_AGENTS_ALLOWED_NETWORKS", "example.com")
    # Mock playwright to avoid actual network call for this unit test
    mock_sync_playwright = mocker.patch("tools.web.browser_snapshot_tool.sync_playwright")
    mock_p = mock_sync_playwright.return_value.__enter__.return_value
    mock_browser = mock_p.chromium.launch.return_value
    mock_context = mock_browser.new_context.return_value
    mock_page = mock_context.new_page.return_value
    
    # Mock return values for extraction
    mock_page.url = "https://example.com/admin"
    mock_page.title.return_value = "Admin Page"
    mock_page.content.return_value = "<html><body>Admin</body></html>"
    mock_page.eval_on_selector.return_value = "Admin"
    mock_page.eval_on_selector_all.return_value = []
    mock_context.cookies.return_value = [{"name": "admin", "value": "true"}]

    tool = BrowserSnapshotTool(results_dir=str(tmp_path))
    test_cookies = [{"name": "admin", "value": "true"}]
    
    res = tool.snapshot("https://example.com/admin", cookies=test_cookies)

    # Verify cookies were added to the context
    # Note: Our tool now normalizes cookies before calling add_cookies
    assert mock_context.add_cookies.called
    
    assert res.title == "Admin Page"
    assert res.text_preview == "Admin"
    assert res.cookies == []
    assert res.local_storage == {}
    assert res.session_storage == {}

    snapshot = json.loads(Path(res.json_path).read_text())
    assert snapshot["cookies"] == []
    assert snapshot["local_storage"] == {}
    assert snapshot["session_storage"] == {}
    assert "admin" not in json.dumps(snapshot["cookies"])


def test_browser_snapshot_persists_session_state_only_when_enabled(tmp_path: Path, mocker, monkeypatch):
    monkeypatch.setenv("CTF_AGENTS_ALLOWED_NETWORKS", "example.com")
    monkeypatch.setenv("CTF_AGENTS_CAPTURE_SENSITIVE_ARTIFACTS", "1")
    mock_sync_playwright = mocker.patch("tools.web.browser_snapshot_tool.sync_playwright")
    mock_p = mock_sync_playwright.return_value.__enter__.return_value
    mock_browser = mock_p.chromium.launch.return_value
    mock_context = mock_browser.new_context.return_value
    mock_page = mock_context.new_page.return_value

    mock_page.url = "https://example.com/admin"
    mock_page.title.return_value = "Admin Page"
    mock_page.content.return_value = "<html><body>Admin</body></html>"
    mock_page.eval_on_selector.return_value = "Admin"
    mock_page.eval_on_selector_all.return_value = []
    mock_page.evaluate.side_effect = [
        {"jwt": "secret-jwt"},
        {"csrf": "secret-csrf"},
    ]
    mock_context.cookies.return_value = [{"name": "admin", "value": "true"}]

    tool = BrowserSnapshotTool(results_dir=str(tmp_path))

    res = tool.snapshot("https://example.com/admin")

    snapshot = json.loads(Path(res.json_path).read_text())
    assert snapshot["cookies"] == [{"name": "admin", "value": "true"}]
    assert snapshot["local_storage"] == {"jwt": "secret-jwt"}
    assert snapshot["session_storage"] == {"csrf": "secret-csrf"}


def test_browser_snapshot_blocks_non_allowlisted_host(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_AGENTS_ALLOWED_NETWORKS", "ctf.local")
    tool = BrowserSnapshotTool(results_dir=str(tmp_path))

    with pytest.raises(SecurityPolicyError):
        tool.snapshot("https://example.com", timeout_s=1)

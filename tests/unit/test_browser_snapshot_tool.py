import pytest
from pathlib import Path

# Skip this test cleanly if Playwright isn't installed in some environments.
pytest.importorskip("playwright")

from tools.web.browser_snapshot_tool import BrowserSnapshotTool


def test_browser_snapshot_example_com_smoke(tmp_path: Path) -> None:
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

    # And should have some content for this page
    assert len(res.text_preview) > 0
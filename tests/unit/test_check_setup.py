from check_setup import _load_nvidia_keys, _playwright_failure_message


def test_load_nvidia_keys_reads_fallback_list(monkeypatch):
    monkeypatch.setenv("NVAPI_KEYS", "nvapi-first, nvapi-second")
    monkeypatch.delenv("NVAPI_KEY", raising=False)
    monkeypatch.delenv("NGC_API_KEY", raising=False)

    assert _load_nvidia_keys() == ["nvapi-first", "nvapi-second"]


def test_load_nvidia_keys_deduplicates_across_env_vars(monkeypatch):
    monkeypatch.setenv("NVAPI_KEYS", "nvapi-first, nvapi-second")
    monkeypatch.setenv("NVAPI_KEY", "nvapi-first")
    monkeypatch.setenv("NGC_API_KEY", "nvapi-third")

    assert _load_nvidia_keys() == ["nvapi-first", "nvapi-second", "nvapi-third"]


def test_playwright_missing_browser_points_to_install():
    status, remediation = _playwright_failure_message(
        RuntimeError("Executable doesn't exist at /tmp/chromium")
    )

    assert "NOT FOUND" in status
    assert "playwright install chromium" in remediation


def test_playwright_launch_failure_does_not_claim_missing_browser():
    status, remediation = _playwright_failure_message(
        RuntimeError("EPERM: operation not permitted, mkdir '/private/tmp/playwright'")
    )

    assert "LAUNCH FAILED" in status
    assert "NOT FOUND" not in status
    assert "sandbox, temp directory, or OS permissions" in remediation

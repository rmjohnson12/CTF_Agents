"""Optional Playwright browser fallback for UI-only HTB actions.

This is a *fallback of last resort*, used only when a needed action is not
exposed by the documented API. It is intentionally a thin, opt-in scaffold: it
does not automate login (which must not be brute-forced) and it never runs
unless the operator passes ``--browser-fallback`` and Playwright is installed.

Actions here are UI-scoped stubs marked TODO until verified against the live
site, so we never pretend to perform an action we have not confirmed.
"""
from __future__ import annotations

import logging
from typing import Optional

from .errors import HTBError

logger = logging.getLogger(__name__)

HTB_APP_URL = "https://app.hackthebox.com"


class BrowserUnavailableError(HTBError):
    """Playwright is not installed or a browser could not be launched."""


def playwright_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except Exception:
        return False


class BrowserFallback:
    """Thin wrapper around a Playwright session authenticated by cookie/token.

    Constructed lazily so importing this module never requires Playwright. All
    action methods are explicit stubs that raise until verified, so callers get
    a clean, honest failure instead of a silent no-op.
    """

    def __init__(self, token: Optional[str] = None, headless: bool = True):
        if not playwright_available():
            raise BrowserUnavailableError(
                "Playwright is not installed. Install with "
                "`pip install playwright && python -m playwright install chromium`."
            )
        self.token = token
        self.headless = headless
        self._browser = None
        self._context = None

    def __enter__(self) -> "BrowserFallback":
        from playwright.sync_api import sync_playwright

        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=self.headless)
        self._context = self._browser.new_context()
        return self

    def __exit__(self, *exc) -> None:
        try:
            if self._browser:
                self._browser.close()
            if getattr(self, "_pw", None):
                self._pw.stop()
        except Exception:  # pragma: no cover - best effort teardown
            pass

    # --- UI-only actions (verify against live site before enabling) ---------
    def download_challenge_files(self, challenge_id: int, dest_dir: str) -> None:  # pragma: no cover - stub
        raise NotImplementedError(
            "Browser download fallback is not implemented/verified. Prefer the API "
            "download endpoint; enable this only after confirming the UI flow."
        )

    def start_instance(self, challenge_id: int) -> None:  # pragma: no cover - stub
        raise NotImplementedError(
            "Browser instance-start fallback is not implemented/verified. Prefer the "
            "API start endpoint."
        )

    def submit_flag(self, challenge_id: int, flag: str) -> None:  # pragma: no cover - stub
        raise NotImplementedError(
            "Browser flag-submission fallback is not implemented/verified and must "
            "never run without explicit operator intent."
        )

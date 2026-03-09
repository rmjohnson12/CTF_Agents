from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

_WS_RE = re.compile(r"\s+")

DEFAULT_VIEWPORT = {"width": 1280, "height": 720}
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def _norm_ws(s: str) -> str:
    return _WS_RE.sub(" ", s).strip()


def _truncate(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    return s[:n] + "\n...[truncated]..."


@dataclass
class BrowserSnapshotResult:
    url: str
    final_url: str
    title: str
    http_status: Optional[int]
    elapsed_s: float

    # Primary extracted signals
    links: List[str]
    forms: List[Dict[str, Any]]
    text_preview: str

    # High-value CTF signals
    cookies: List[Dict[str, Any]]
    script_srcs: List[str]
    hidden_inputs: List[Dict[str, str]]

    # Saved artifacts
    screenshot_path: str
    html_path: str
    json_path: str


class BrowserSnapshotTool:
    """
    MVP Playwright snapshot utility for web recon.

    Goals:
    - load a URL in a real browser context (JS-rendered)
    - extract links/forms/visible text (bounded)
    - save screenshot + rendered HTML + JSON snapshot to results/
    - return structured metadata for agent consumption
    """

    def __init__(
        self,
        *,
        results_dir: str = "results",
        max_text_chars: int = 20_000,
        max_links: int = 500,
        max_forms: int = 200,
    ):
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)

        self.max_text_chars = max_text_chars
        self.max_links = max_links
        self.max_forms = max_forms

    def snapshot(
        self,
        url: str,
        *,
        timeout_s: int = 30,
        wait_until: str = "networkidle",
        allow_downloads: bool = False,
    ) -> BrowserSnapshotResult:
        started = time.time()

        # Use a timestamp to avoid clobbering runs
        ts = time.strftime("%Y%m%d_%H%M%S")
        run_dir = self.results_dir / f"browser_snapshot_{ts}"
        run_dir.mkdir(parents=True, exist_ok=True)

        screenshot_path = run_dir / "screenshot.png"
        html_path = run_dir / "page.html"
        json_path = run_dir / "snapshot.json"

        final_url = url
        title = ""
        status: Optional[int] = None
        links: List[str] = []
        forms: List[Dict[str, Any]] = []
        text_preview = ""
        cookies: List[Dict[str, Any]] = []
        script_srcs: List[str] = []
        hidden_inputs: List[Dict[str, str]] = []

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)

                context = browser.new_context(
                    viewport=DEFAULT_VIEWPORT,
                    user_agent=DEFAULT_USER_AGENT,
                    accept_downloads=allow_downloads,
                )
                page = context.new_page()

                resp = page.goto(url, wait_until=wait_until, timeout=timeout_s * 1000)
                if resp is not None:
                    status = int(resp.status)

                # Small settle for late JS
                page.wait_for_timeout(500)
                # High-value CTF signals
                cookies = context.cookies()

                script_srcs = page.eval_on_selector_all(
                    "script[src]",
                    "els => els.map(s => s.src).filter(Boolean)",
                )

                hidden_inputs = page.eval_on_selector_all(
                    "input[type=hidden]",
                    "els => els.map(i => ({name: i.name || '', id: i.id || '', value: i.value || ''}))",
                )

                final_url = page.url
                title = page.title()

                # Rendered HTML
                html = page.content()
                html_path.write_text(html, encoding="utf-8")

                # Screenshot
                page.screenshot(path=str(screenshot_path), full_page=True)

                # Extract links (absolute)
                # Use page.eval to resolve URLs robustly in-browser
                links = page.eval_on_selector_all(
                    "a[href]",
                    """els => els
                        .map(a => a.href)
                        .filter(Boolean)""",
                )
                # Dedupe while preserving order
                seen = set()
                deduped = []
                for u in links:
                    if u not in seen:
                        seen.add(u)
                        deduped.append(u)
                links = deduped[: self.max_links]

                # Extract forms + inputs
                forms = page.eval_on_selector_all(
                    "form",
                    """forms => forms.slice(0, 1000).map(f => {
                        const action = f.action || "";
                        const method = (f.method || "GET").toUpperCase();
                        const inputs = Array.from(f.querySelectorAll("input, textarea, select")).map(el => {
                            const tag = el.tagName.toLowerCase();
                            const type = (el.getAttribute("type") || "").toLowerCase();
                            return {
                                tag,
                                type,
                                name: el.getAttribute("name") || "",
                                id: el.getAttribute("id") || "",
                                value: (el.getAttribute("value") || ""),
                                required: el.hasAttribute("required"),
                            };
                        });
                        return { action, method, inputs };
                    })""",
                )
                forms = forms[: self.max_forms]

                # Visible text (bounded + normalized)
                body_text = page.eval_on_selector(
                    "body", "el => (el && el.innerText) ? el.innerText : ''"
                )
                text_preview = _truncate(_norm_ws(body_text or ""), self.max_text_chars)

                browser.close()

        except PlaywrightTimeoutError:
            # Keep whatever we have; title/status may be empty
            pass

        elapsed = time.time() - started

        payload = {
            "url": url,
            "final_url": final_url,
            "title": title,
            "http_status": status,
            "elapsed_s": elapsed,
            "links": links,
            "forms": forms,
            "text_preview": text_preview,
            "cookies": cookies,
            "script_srcs": script_srcs,
            "hidden_inputs": hidden_inputs,
            "artifacts": {
                "screenshot_path": str(screenshot_path),
                "html_path": str(html_path),
                "json_path": str(json_path),
            },
        }
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        return BrowserSnapshotResult(
            url=url,
            final_url=final_url,
            title=title,
            http_status=status,
            elapsed_s=elapsed,
            links=links,
            forms=forms,
            text_preview=text_preview,
            cookies=cookies,
            script_srcs=script_srcs,
            hidden_inputs=hidden_inputs,
            screenshot_path=str(screenshot_path),
            html_path=str(html_path),
            json_path=str(json_path),
        )
if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python tools/web/browser_snapshot_tool.py <url>")
        raise SystemExit(2)

    tool = BrowserSnapshotTool()
    result = tool.snapshot(sys.argv[1])

    print(json.dumps(
        {
            "title": result.title,
            "final_url": result.final_url,
            "http_status": result.http_status,
            "links": len(result.links),
            "forms": len(result.forms),
            "cookies": len(result.cookies),
            "script_srcs": len(result.script_srcs),
            "hidden_inputs": len(result.hidden_inputs),
            "artifacts": {
                "screenshot_path": result.screenshot_path,
                "html_path": result.html_path,
                "json_path": result.json_path,
            },
        },
        indent=2,
    ))
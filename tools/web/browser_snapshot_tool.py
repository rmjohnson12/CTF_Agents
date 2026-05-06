from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from playwright.sync_api import sync_playwright

_WS_RE = re.compile(r"\s+")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

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


def _extract_title_from_html(html: str) -> str:
    if not html:
        return ""
    match = _TITLE_RE.search(html)
    if not match:
        return ""
    return _norm_ws(match.group(1))


def _json_safe_mapping(value: Any) -> Dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v) for k, v in value.items()}


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
    html_content: str

    # High-value CTF signals
    cookies: List[Dict[str, Any]]
    script_srcs: List[str]
    hidden_inputs: List[Dict[str, str]]
    local_storage: Dict[str, str]
    session_storage: Dict[str, str]

    # Saved artifacts
    screenshot_path: str
    html_path: str
    json_path: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "title": self.title,
            "http_status": self.http_status,
            "elapsed_s": self.elapsed_s,
            "links": self.links,
            "forms": self.forms,
            "text_preview": self.text_preview,
            "html_content": self.html_content,
            "cookies": self.cookies,
            "script_srcs": self.script_srcs,
            "hidden_inputs": self.hidden_inputs,
            "local_storage": self.local_storage,
            "session_storage": self.session_storage,
            "artifacts": {
                "screenshot_path": self.screenshot_path,
                "html_path": self.html_path,
                "json_path": self.json_path,
            }
        }


class BrowserSnapshotTool:
    """
    MVP Playwright snapshot utility for web recon.
    """

    def __init__(
        self,
        *,
        results_dir: str = "results",
        max_text_chars: int = 20_000,
        max_links: int = 500,
        max_forms: int = 200,
        max_runs_to_keep: int = 5,
    ):
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)

        self.max_text_chars = max_text_chars
        self.max_links = max_links
        self.max_forms = max_forms
        self.max_runs_to_keep = max_runs_to_keep

    def cleanup(self):
        """Delete old snapshot folders to keep results dir clean."""
        try:
            dirs = sorted(
                [d for d in self.results_dir.iterdir() if d.is_dir() and (d.name.startswith("browser_snapshot_") or d.name.startswith("form_submit_"))],
                key=lambda x: x.stat().st_mtime,
                reverse=True
            )
            if len(dirs) > self.max_runs_to_keep:
                import shutil
                for old_dir in dirs[self.max_runs_to_keep:]:
                    shutil.rmtree(old_dir)
        except:
            pass

    def run(self, url: str, **kwargs) -> BrowserSnapshotResult:
        """Alias for snapshot() to match BaseTool interface."""
        return self.snapshot(url, **kwargs)

    def snapshot(
        self,
        url: str,
        *,
        timeout_s: int = 30,
        wait_until: str = "networkidle",
        cookies: Optional[List[Dict[str, Any]]] = None,
    ) -> BrowserSnapshotResult:
        self.cleanup()
        started = time.time()
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
        html_content = ""
        captured_cookies: List[Dict[str, Any]] = []
        script_srcs: List[str] = []
        hidden_inputs: List[Dict[str, str]] = []
        local_storage: Dict[str, str] = {}
        session_storage: Dict[str, str] = {}

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                
                processed_cookies = []
                if cookies:
                    from urllib.parse import urlparse
                    parsed_url = urlparse(url)
                    domain = parsed_url.netloc.split(':')[0]
                    for c in cookies:
                        nc = c.copy()
                        if 'domain' not in nc: nc['domain'] = domain
                        if 'path' not in nc: nc['path'] = '/'
                        if 'url' in nc: del nc['url']
                        processed_cookies.append(nc)

                context = browser.new_context(viewport=DEFAULT_VIEWPORT, user_agent=DEFAULT_USER_AGENT)
                if processed_cookies:
                    context.add_cookies(processed_cookies)
                
                page = context.new_page()
                resp = page.goto(url, wait_until=wait_until, timeout=timeout_s * 1000)
                if resp is not None: status = int(resp.status)

                # Wait for core DOM content, then a small settle
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=timeout_s * 1000)
                except:
                    pass
                page.wait_for_timeout(1000) 

                captured_cookies = context.cookies()
                script_srcs = page.eval_on_selector_all("script[src]", "els => els.map(s => s.src).filter(Boolean)")
                hidden_inputs = page.eval_on_selector_all("input[type=hidden]", "els => els.map(i => ({name: i.name || '', id: i.id || '', value: i.value || ''}))")
                
                try:
                    local_storage = _json_safe_mapping(page.evaluate("() => ({...localStorage})"))
                    session_storage = _json_safe_mapping(page.evaluate("() => ({...sessionStorage})"))
                except:
                    local_storage = {}
                    session_storage = {}

                final_url = page.url
                title = page.title()
                
                html_content = page.content()
                if not title:
                    title = _extract_title_from_html(html_content)

                html_path.write_text(html_content, encoding="utf-8")
                page.screenshot(path=str(screenshot_path), full_page=True)

                links = page.eval_on_selector_all("a[href]", "els => els.map(a => a.href).filter(Boolean)")
                seen = set()
                links = [u for u in links if not (u in seen or seen.add(u))][:self.max_links]

                forms = page.eval_on_selector_all("form", """forms => forms.map(f => {
                    const action = f.action || "";
                    const method = (f.method || "GET").toUpperCase();
                    const inputs = Array.from(f.querySelectorAll("input, textarea, select")).map(el => ({
                        tag: el.tagName.toLowerCase(),
                        type: (el.getAttribute("type") || "").toLowerCase(),
                        name: el.getAttribute("name") || "",
                        id: el.getAttribute("id") || "",
                        value: (el.getAttribute("value") || ""),
                    }));
                    return { action, method, inputs };
                })""")[:self.max_forms]

                body_text = page.eval_on_selector("body", "el => (el && el.innerText) ? el.innerText : ''")
                text_preview = _truncate(_norm_ws(body_text or ""), self.max_text_chars)
                browser.close()
        except Exception as e:
            text_preview = f"Snapshot failed: {e}"
            html_content = text_preview

        elapsed = time.time() - started
        
        # Save JSON snapshot
        result_dict = {
            "url": url, "final_url": final_url, "title": title, "http_status": status,
            "elapsed_s": elapsed, "links": links, "forms": forms, 
            "text_preview": text_preview, "html_content": html_content,
            "cookies": captured_cookies, "script_srcs": script_srcs, "hidden_inputs": hidden_inputs,
            "local_storage": local_storage, "session_storage": session_storage,
            "artifacts": {
                "screenshot_path": str(screenshot_path),
                "html_path": str(html_path),
                "json_path": str(json_path),
            }
        }
        json_path.write_text(json.dumps(result_dict, indent=2), encoding="utf-8")

        return BrowserSnapshotResult(
            url, final_url, title, status, elapsed, links, forms, text_preview, html_content,
            captured_cookies, script_srcs, hidden_inputs, local_storage, session_storage,
            str(screenshot_path), str(html_path), str(json_path)
        )

    def submit_form(
        self,
        url: str,
        form_meta: Dict[str, Any],
        form_data: Dict[str, Any],
        *,
        timeout_s: int = 30,
        wait_until: str = "networkidle",
        cookies: Optional[List[Dict[str, Any]]] = None,
    ) -> BrowserSnapshotResult:
        self.cleanup()
        started = time.time()
        ts = time.strftime("%Y%m%d_%H%M%S")
        run_dir = self.results_dir / f"form_submit_{ts}"
        run_dir.mkdir(parents=True, exist_ok=True)

        screenshot_path = run_dir / "screenshot.png"
        html_path = run_dir / "page.html"
        json_path = run_dir / "snapshot.json"

        final_url = url
        title = ""
        status: Optional[int] = None
        text_preview = ""
        html_content = ""
        captured_cookies: List[Dict[str, Any]] = []

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                
                processed_cookies = []
                if cookies:
                    from urllib.parse import urlparse
                    parsed_url = urlparse(url)
                    domain = parsed_url.netloc.split(':')[0]
                    for c in cookies:
                        nc = c.copy()
                        if 'domain' not in nc: nc['domain'] = domain
                        if 'path' not in nc: nc['path'] = '/'
                        if 'url' in nc: del nc['url']
                        processed_cookies.append(nc)

                context = browser.new_context(viewport=DEFAULT_VIEWPORT, user_agent=DEFAULT_USER_AGENT)
                if processed_cookies:
                    context.add_cookies(processed_cookies)
                
                page = context.new_page()
                page.goto(url, wait_until=wait_until, timeout=timeout_s * 1000)
                for name, value in form_data.items():
                    selector = f'input[name="{name}"], input[id="{name}"], textarea[name="{name}"], select[name="{name}"]'
                    try:
                        page.wait_for_selector(selector, timeout=2000)
                        page.fill(selector, str(value))
                    except: pass
                
                try:
                    submit_selector = 'input[type="submit"], button[type="submit"], button:has-text("Login"), button:has-text("Sign In")'
                    if page.query_selector(submit_selector): page.click(submit_selector)
                    else: page.keyboard.press("Enter")
                except: page.keyboard.press("Enter")

                try:
                    page.wait_for_load_state("domcontentloaded", timeout=5000)
                except:
                    pass
                page.wait_for_timeout(1000)
                final_url = page.url
                title = page.title()
                html_content = page.content()
                if not title:
                    title = _extract_title_from_html(html_content)

                html_path.write_text(html_content, encoding="utf-8")
                page.screenshot(path=str(screenshot_path), full_page=True)
                captured_cookies = context.cookies()
                try:
                    local_storage = page.evaluate("() => ({...localStorage})")
                    session_storage = page.evaluate("() => ({...sessionStorage})")
                except:
                    local_storage = {}
                    session_storage = {}
                body_text = page.eval_on_selector("body", "el => (el && el.innerText) ? el.innerText : ''")
                text_preview = _truncate(_norm_ws(body_text or ""), self.max_text_chars)
                browser.close()
        except Exception as e:
            text_preview = f"Form submission failed: {e}"
            html_content = text_preview

        elapsed = time.time() - started
        
        # Save JSON snapshot
        result_dict = {
            "url": url, "final_url": final_url, "title": title, "http_status": status,
            "elapsed_s": elapsed, "links": [], "forms": [], 
            "text_preview": text_preview, "html_content": html_content,
            "cookies": captured_cookies, "script_srcs": [], "hidden_inputs": [],
            "local_storage": local_storage if 'local_storage' in locals() else {},
            "session_storage": session_storage if 'session_storage' in locals() else {},
            "artifacts": {
                "screenshot_path": str(screenshot_path),
                "html_path": str(html_path),
                "json_path": str(json_path),
            }
        }
        json_path.write_text(json.dumps(result_dict, indent=2), encoding="utf-8")

        return BrowserSnapshotResult(
            url, final_url, title, status, elapsed, [], [], text_preview, html_content,
            captured_cookies, [], [], 
            local_storage if 'local_storage' in locals() else {}, 
            session_storage if 'session_storage' in locals() else {},
            str(screenshot_path), str(html_path), str(json_path)
        )

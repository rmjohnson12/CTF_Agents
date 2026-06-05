from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, Optional, Any

import requests

from core.utils.security import assert_url_allowed


@dataclass
class HttpFetchResult:
    url: str
    final_url: str
    method: str
    status_code: int
    headers: Dict[str, str]
    body_preview: str
    elapsed_s: float
    cookies: Dict[str, str] = field(default_factory=dict)


@dataclass
class HttpContentResult:
    url: str
    final_url: str
    method: str
    status_code: int
    headers: Dict[str, str]
    content: bytes
    elapsed_s: float
    cookies: Dict[str, str] = field(default_factory=dict)


class HttpFetchTool:
    """
    MVP HTTP fetch utility for web recon.
    """

    def __init__(self, *, max_preview_chars: int = 10000):
        self.max_preview_chars = max_preview_chars

    def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        timeout_s: int = 15,
        allow_redirects: bool = True,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        json_data: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
        cookies: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> HttpFetchResult:
        method = method.upper()
        assert_url_allowed(url)
        resp = requests.request(
            method=method,
            url=url,
            timeout=timeout_s,
            allow_redirects=False,
            headers=headers,
            data=data,
            json=json_data,
            files=files,
            cookies=cookies,
            params=params
        )
        redirects_remaining = 10
        while allow_redirects and getattr(resp, "is_redirect", False) and redirects_remaining > 0:
            location = resp.headers.get("Location")
            if not location:
                break
            next_url = requests.compat.urljoin(str(resp.url), location)
            assert_url_allowed(next_url)
            resp = requests.request(
                method="GET",
                url=next_url,
                timeout=timeout_s,
                allow_redirects=False,
                headers=headers,
                cookies=cookies,
            )
            redirects_remaining -= 1

        # Keep headers simple/serializable
        hdrs = {str(k): str(v) for k, v in resp.headers.items()}
        captured_cookies = {}
        if hasattr(resp, 'cookies') and hasattr(resp.cookies, 'get_dict'):
            captured_cookies = resp.cookies.get_dict()

        text = resp.text if resp.text is not None else ""
        preview = text[: self.max_preview_chars]
        if len(text) > self.max_preview_chars:
            preview += "\n...[truncated]..."

        return HttpFetchResult(
            url=url,
            final_url=str(resp.url),
            method=method,
            status_code=int(resp.status_code),
            headers=hdrs,
            body_preview=preview,
            elapsed_s=float(resp.elapsed.total_seconds()),
            cookies=captured_cookies
        )

    def fetch_content(
        self,
        url: str,
        *,
        method: str = "GET",
        timeout_s: int = 15,
        allow_redirects: bool = True,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        max_bytes: int = 2_000_000,
    ) -> HttpContentResult:
        method = method.upper()
        assert_url_allowed(url)
        resp = requests.request(
            method=method,
            url=url,
            timeout=timeout_s,
            allow_redirects=False,
            headers=headers,
            cookies=cookies,
        )
        redirects_remaining = 10
        while allow_redirects and getattr(resp, "is_redirect", False) and redirects_remaining > 0:
            location = resp.headers.get("Location")
            if not location:
                break
            next_url = requests.compat.urljoin(str(resp.url), location)
            assert_url_allowed(next_url)
            resp = requests.request(
                method="GET",
                url=next_url,
                timeout=timeout_s,
                allow_redirects=False,
                headers=headers,
                cookies=cookies,
            )
            redirects_remaining -= 1

        hdrs = {str(k): str(v) for k, v in resp.headers.items()}
        captured_cookies = {}
        if hasattr(resp, "cookies") and hasattr(resp.cookies, "get_dict"):
            captured_cookies = resp.cookies.get_dict()

        return HttpContentResult(
            url=url,
            final_url=str(resp.url),
            method=method,
            status_code=int(resp.status_code),
            headers=hdrs,
            content=bytes(resp.content[:max_bytes]),
            elapsed_s=float(resp.elapsed.total_seconds()),
            cookies=captured_cookies,
        )

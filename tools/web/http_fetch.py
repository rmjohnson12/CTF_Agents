from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

import requests


@dataclass
class HttpFetchResult:
    url: str
    final_url: str
    method: str
    status_code: int
    headers: Dict[str, str]
    body_preview: str
    elapsed_s: float


class HttpFetchTool:
    """
    MVP HTTP fetch utility for web recon.

    Goals:
    - fetch a URL safely (timeout, redirect handling)
    - return structured metadata + a truncated body preview
    """

    def __init__(self, *, max_preview_chars: int = 5000):
        self.max_preview_chars = max_preview_chars

    def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        timeout_s: int = 15,
        allow_redirects: bool = True,
        headers: Optional[Dict[str, str]] = None,
    ) -> HttpFetchResult:
        resp = requests.request(
            method=method.upper(),
            url=url,
            timeout=timeout_s,
            allow_redirects=allow_redirects,
            headers=headers,
        )

        # Keep headers simple/serializable
        hdrs = {str(k): str(v) for k, v in resp.headers.items()}

        text = resp.text if resp.text is not None else ""
        preview = text[: self.max_preview_chars]
        if len(text) > self.max_preview_chars:
            preview += "\n...[truncated]..."

        return HttpFetchResult(
            url=url,
            final_url=str(resp.url),
            method=method.upper(),
            status_code=int(resp.status_code),
            headers=hdrs,
            body_preview=preview,
            elapsed_s=float(getattr(resp.elapsed, "total_seconds", lambda: 0.0)()),
        )
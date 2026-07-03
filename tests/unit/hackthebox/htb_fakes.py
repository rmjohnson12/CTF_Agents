"""Shared no-network fakes for HTB integration unit tests."""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, content=b"", headers=None):
        self.status_code = status_code
        self._json = json_data
        self.content = content
        self.headers = headers or {}
        self.text = json.dumps(json_data) if json_data is not None else ""

    def json(self):
        if self._json is None:
            raise ValueError("no json body")
        return self._json


Handler = Callable[[str, str, Optional[dict], Optional[dict]], FakeResponse]


class FakeSession:
    """Minimal stand-in for requests.Session used by HTBClient/auth."""

    def __init__(self, handler: Handler):
        self._handler = handler
        self.headers: Dict[str, str] = {}
        self.calls: List[Dict[str, Any]] = []

    def request(self, method, url, params=None, json=None, timeout=None):
        self.calls.append({"method": method, "url": url, "params": params, "json": json})
        return self._handler(method, url, params, json)

    def post(self, url, json=None, headers=None, timeout=None):
        self.calls.append({"method": "POST", "url": url, "params": None, "json": json})
        return self._handler("POST", url, None, json)


def route_handler(routes: Dict[str, FakeResponse]) -> Handler:
    """Return a handler matching by URL suffix/substring (first match wins)."""

    def handler(method, url, params, json):
        for suffix, response in routes.items():
            if url.endswith(suffix) or suffix in url:
                return response
        return FakeResponse(404, {"message": "not found"})

    return handler


def queue_handler(responses: List[FakeResponse]) -> Handler:
    """Return a handler that yields queued responses in order (for retries)."""
    box = list(responses)

    def handler(method, url, params, json):
        return box.pop(0) if box else FakeResponse(500, {"message": "exhausted"})

    return handler

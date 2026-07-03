"""HTTP client for the Hack The Box v4 API.

Design rules driven by the community-maintained (i.e. unverified) docs:
  * Every response is parsed defensively; unexpected shapes raise
    ``HTBEndpointError`` with the endpoint's confidence note attached.
  * Auth failures, 404s, and rate limits map to distinct exception types so the
    runner can react appropriately (abort vs. skip vs. back off).
  * The bearer token is never logged; ``_safe_str`` redacts it if it ever
    appears in a URL/message.
"""
from __future__ import annotations

import html
import logging
import time
from typing import Any, Dict, List, Optional

import requests

from .config import HTBConfig, Endpoint
from .errors import (
    HTBError,
    HTBAPIError,
    HTBAuthError,
    HTBEndpointError,
    HTBNotFoundError,
    HTBRateLimitError,
)
from .models import Challenge, SpawnInfo

logger = logging.getLogger(__name__)

_MAX_RATE_LIMIT_RETRIES = 2
_MAX_RATE_LIMIT_SLEEP = 30.0


def redact_token(token: Optional[str]) -> str:
    if not token:
        return "<none>"
    if len(token) <= 8:
        return "***"
    return f"{token[:4]}…{token[-2:]}"


class HTBClient:
    """Thin, defensive wrapper over the HTB v4 REST API."""

    def __init__(
        self,
        token: str,
        config: Optional[HTBConfig] = None,
        session: Optional[requests.Session] = None,
        sleeper=time.sleep,
    ):
        if not token:
            raise HTBAuthError("HTBClient requires a bearer token.")
        self._token = token
        self.config = config or HTBConfig()
        self.session = session or requests.Session()
        self._sleep = sleeper
        self._category_map: Optional[Dict[int, str]] = None
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "User-Agent": self.config.user_agent,
                "Accept": "application/json, application/octet-stream",
            }
        )

    # ------------------------------------------------------------------ core
    def _url(self, endpoint: Endpoint, **path_params) -> str:
        return f"{self.config.api_base}{endpoint.format(**path_params)}"

    def _safe_str(self, text: str) -> str:
        return text.replace(self._token, redact_token(self._token)) if self._token else text

    def _request(
        self,
        endpoint_name: str,
        *,
        path_params: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        expect: str = "json",
    ):
        endpoint = self.config.endpoint(endpoint_name)
        url = self._url(endpoint, **(path_params or {}))
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = self.session.request(
                    endpoint.method,
                    url,
                    params=params,
                    json=json_body,
                    timeout=self.config.timeout_seconds,
                )
            except requests.RequestException as exc:
                raise HTBAPIError(self._safe_str(f"Network error calling {endpoint_name}: {exc}")) from exc

            if resp.status_code == 429 and attempt <= _MAX_RATE_LIMIT_RETRIES:
                delay = _retry_after_seconds(resp) or (2.0 * attempt)
                logger.warning("HTB rate limit on %s; backing off %.1fs", endpoint_name, delay)
                self._sleep(min(delay, _MAX_RATE_LIMIT_SLEEP))
                continue

            return self._handle_response(endpoint_name, endpoint, resp, expect)

    def _handle_response(self, endpoint_name: str, endpoint: Endpoint, resp: requests.Response, expect: str):
        status = resp.status_code
        if status in (401, 403):
            raise HTBAuthError(
                f"Authentication failed on {endpoint_name} (HTTP {status}). "
                "Check HTB_TOKEN / session validity and account access."
            )
        if status == 429:
            raise HTBRateLimitError(
                f"Rate limited on {endpoint_name} (HTTP 429).",
                retry_after=_retry_after_seconds(resp),
            )
        if status == 404:
            raise HTBNotFoundError(
                f"Not found on {endpoint_name} (HTTP 404). "
                f"If unexpected, the '{endpoint.confidence}'-confidence endpoint may have changed: {endpoint.note}"
            )
        if status >= 400:
            raise HTBAPIError(
                self._safe_str(f"{endpoint_name} failed (HTTP {status}): {resp.text[:300]}"),
                status_code=status,
            )

        if expect == "bytes":
            return resp.content
        try:
            return resp.json()
        except ValueError as exc:
            raise HTBEndpointError(
                f"{endpoint_name} returned non-JSON (HTTP {status}). "
                f"The '{endpoint.confidence}'-confidence endpoint may have changed: {endpoint.note}"
            ) from exc

    # ------------------------------------------------------------------ API
    def get_user_info(self) -> Dict[str, Any]:
        """Return the authenticated user's profile (also validates the token)."""
        data = self._request("user_info")
        info = _first_dict(data, ("info", "user", "data")) or (data if isinstance(data, dict) else {})
        if not info:
            raise HTBEndpointError("user_info returned an unrecognised shape.")
        return info

    def list_categories(self) -> Dict[int, str]:
        """Return a {category_id: name} map, cached for the client's lifetime."""
        if self._category_map is not None:
            return self._category_map
        data = self._request("categories")
        items = _first_list(data, ("info", "categories", "data")) or (data if isinstance(data, list) else [])
        mapping: Dict[int, str] = {}
        for item in items:
            if isinstance(item, dict) and "id" in item:
                mapping[int(item["id"])] = str(item.get("name") or item.get("category") or item["id"])
        self._category_map = mapping
        return mapping

    def list_challenges(self, retired: bool = False) -> List[Challenge]:
        """List active (or retired) challenges accessible to the account."""
        endpoint_name = "challenge_list_retired" if retired else "challenge_list"
        data = self._request(endpoint_name)
        items = _first_list(data, ("challenges", "data", "info")) or (data if isinstance(data, list) else None)
        if items is None:
            raise HTBEndpointError(
                f"{endpoint_name} returned an unrecognised shape "
                f"(keys={list(data)[:10] if isinstance(data, dict) else type(data).__name__}). "
                "Verify the endpoint against current API docs."
            )
        category_map = self._safe_category_map()
        return [_build_challenge(item, category_map, retired=retired) for item in items if isinstance(item, dict)]

    def get_challenge(self, challenge_id: int) -> Challenge:
        data = self._request("challenge_info", path_params={"challenge_id": challenge_id})
        raw = _first_dict(data, ("challenge", "info", "data")) or (data if isinstance(data, dict) else None)
        if not raw:
            raise HTBEndpointError(f"challenge_info for {challenge_id} returned an unrecognised shape.")
        return _build_challenge(raw, self._safe_category_map())

    def download_challenge(self, challenge_id: int) -> bytes:
        """Return the raw challenge archive bytes (caller extracts safely)."""
        content = self._request("challenge_download", path_params={"challenge_id": challenge_id}, expect="bytes")
        if not content:
            raise HTBEndpointError(f"challenge_download for {challenge_id} returned empty content.")
        return content

    def start_instance(self, challenge_id: int) -> SpawnInfo:
        """Spawn a challenge container and wait for its IP:PORT.

        ``POST /container/start`` is asynchronous (returns only "Instance
        Created!" + id); the IP/ports appear in the challenge's ``play_info``
        once the container is ready, so we poll for them (bounded by
        ``spawn_timeout_seconds``). Reuses an already-running instance.
        """
        info = self._play_info(challenge_id)
        if not info.get("ip"):
            self._request("challenge_start", json_body={"containerable_id": challenge_id})
        deadline = time.monotonic() + self.config.spawn_timeout_seconds
        while True:
            info = self._play_info(challenge_id)
            if info.get("ip"):
                return SpawnInfo(
                    challenge_id=challenge_id,
                    status=str(info.get("status") or "ready"),
                    ip=info.get("ip"),
                    port=info.get("port"),
                    raw=info.get("raw") or {},
                )
            if time.monotonic() >= deadline:
                return SpawnInfo(challenge_id=challenge_id, status="spawn-timeout", raw=info.get("raw") or {})
            self._sleep(self.config.spawn_poll_seconds)

    def _play_info(self, challenge_id: int) -> Dict[str, Any]:
        """Return {ip, port, status, raw} for a challenge's current instance."""
        raw = self.get_challenge(challenge_id).raw
        pi = raw.get("play_info") or {}
        ports = pi.get("ports") or raw.get("docker_ports") or []
        port = ports[0] if isinstance(ports, list) and ports else ports
        return {
            "ip": pi.get("ip") or raw.get("docker_ip"),
            "port": _as_int(port),
            "status": pi.get("status") or raw.get("docker_status"),
            "raw": pi if isinstance(pi, dict) else {},
        }

    def stop_instance(self, challenge_id: int) -> Dict[str, Any]:
        """Stop a spawned container. Body {containerable_id} per HTB frontend."""
        data = self._request("challenge_stop", json_body={"containerable_id": challenge_id})
        return data if isinstance(data, dict) else {"raw": data}

    def submit_flag(self, challenge_id: int, flag: str, difficulty: int = 50) -> Dict[str, Any]:
        """Submit a flag ("own"). Only ever called when --submit is set.

        ``difficulty`` is HTB's post-solve difficulty rating (10..100, multiples
        of 10). It is required by the endpoint; 50 is a neutral default.
        """
        difficulty = max(10, min(100, int(difficulty)))
        data = self._request(
            "challenge_own",
            json_body={"challenge_id": challenge_id, "flag": flag, "difficulty": difficulty},
        )
        return data if isinstance(data, dict) else {"raw": data}

    # ------------------------------------------------------------------ util
    def _safe_category_map(self) -> Dict[int, str]:
        # A missing category map must not abort a listing; fall back to ids.
        try:
            return self.list_categories()
        except HTBError as exc:  # pragma: no cover - defensive
            logger.debug("Category map unavailable, continuing without names: %s", exc)
            return {}


# --------------------------------------------------------------------- parse
def _retry_after_seconds(resp: requests.Response) -> Optional[float]:
    raw = resp.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def _first_list(data: Any, keys) -> Optional[List[Any]]:
    if isinstance(data, dict):
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                return value
    return None


def _first_dict(data: Any, keys) -> Optional[Dict[str, Any]]:
    if isinstance(data, dict):
        for key in keys:
            value = data.get(key)
            if isinstance(value, dict):
                return value
    return None


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)


def _resolve_category(raw: Dict[str, Any], category_map: Dict[int, str]) -> str:
    for key in ("category_name", "category"):
        value = raw.get(key)
        if isinstance(value, str) and value:
            return value
        if isinstance(value, int):
            return category_map.get(value, str(value))
    cat_id = raw.get("challenge_category_id") or raw.get("category_id")
    if isinstance(cat_id, int):
        return category_map.get(cat_id, str(cat_id))
    return "unknown"


def _build_challenge(raw: Dict[str, Any], category_map: Dict[int, str], retired: bool = False) -> Challenge:
    return Challenge(
        id=int(raw.get("id")),
        name=str(raw.get("name") or f"challenge-{raw.get('id')}"),
        category=_resolve_category(raw, category_map),
        difficulty=str(raw.get("difficulty") or raw.get("difficultyText") or raw.get("difficulty_text") or "unknown"),
        description=html.unescape(str(raw.get("description") or "")),
        points=_as_int(raw.get("points")),
        retired=_truthy(raw.get("retired")) or retired,
        solved=_truthy(raw.get("solved") or raw.get("authUserSolve") or raw.get("isSolved")),
        locked=_truthy(raw.get("locked")),
        has_download=_truthy(raw.get("download") or raw.get("has_download")),
        needs_instance=_truthy(raw.get("docker") or raw.get("hasInstance") or raw.get("docker_ip")),
        raw=raw,
    )



def _as_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

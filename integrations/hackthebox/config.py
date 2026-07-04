"""Endpoint table and tunables for the Hack The Box v4 API.

The v4 API docs referenced by this integration are community-maintained
(https://documenter.getpostman.com/view/13129365/TVeqbmeq), so **every path
here is treated as unverified until it succeeds at runtime**. Each entry carries
a confidence note. Anything below "high" confidence must be exercised carefully
and every client method parses defensively and raises ``HTBEndpointError`` (not
a crash) if the response shape is unexpected.

Every value can be overridden from the environment without editing code, so an
operator can repair a changed endpoint immediately:

    HTB_API_BASE=...              base URL
    HTB_EP_USER_INFO=...          per-endpoint path override
    HTB_EP_CHALLENGE_LIST=...     (etc. — see ``ENDPOINT_ENV_KEYS``)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict

# labs.hackthebox.com is the current v4 host; www.hackthebox.com historically
# proxied the same API. Override with HTB_API_BASE if HTB moves it again.
DEFAULT_API_BASE = "https://labs.hackthebox.com/api/v4"

# HTB challenge archives are conventionally zip files protected with this
# password. Overridable; only used for *extraction*, never transmitted.
DEFAULT_ARCHIVE_PASSWORD = "hackthebox"

DEFAULT_TIMEOUT_SECONDS = 30.0
# HTB's edge (nginx) returns 404 for unfamiliar User-Agents, so a browser-like
# UA is required for the API to respond at all. Overridable via HTB_USER_AGENT.
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Bound the wait we will honour for instance spawn / target reachability so a
# stuck instance cannot hang the whole run.
DEFAULT_SPAWN_TIMEOUT_SECONDS = 240.0
DEFAULT_SPAWN_POLL_SECONDS = 8.0


@dataclass(frozen=True)
class Endpoint:
    """A single API path plus a human-readable confidence note.

    ``path`` is a format string relative to the API base. ``confidence`` is one
    of "high" | "medium" | "low" and is surfaced in error messages so failures
    read as "this low-confidence endpoint may have changed" rather than a bug.
    """

    path: str
    method: str = "GET"
    confidence: str = "medium"
    note: str = ""

    def format(self, **kwargs) -> str:
        return self.path.format(**kwargs)


# Maps a logical endpoint name -> the env var that overrides its path.
ENDPOINT_ENV_KEYS: Dict[str, str] = {
    "user_info": "HTB_EP_USER_INFO",
    "login": "HTB_EP_LOGIN",
    "categories": "HTB_EP_CATEGORIES",
    "challenge_list": "HTB_EP_CHALLENGE_LIST",
    "challenge_list_retired": "HTB_EP_CHALLENGE_LIST_RETIRED",
    "challenge_info": "HTB_EP_CHALLENGE_INFO",
    "challenge_download": "HTB_EP_CHALLENGE_DOWNLOAD",
    "challenge_start": "HTB_EP_CHALLENGE_START",
    "challenge_stop": "HTB_EP_CHALLENGE_STOP",
    "challenge_own": "HTB_EP_CHALLENGE_OWN",
}


def _default_endpoints() -> Dict[str, Endpoint]:
    return {
        # High confidence: stable, widely used for token verification.
        "user_info": Endpoint("/user/info", "GET", "high", "Authenticated user profile."),
        # Login/2FA flow is intentionally low confidence — App Token auth is the
        # supported programmatic path and is preferred. See auth.py.
        "login": Endpoint("/login", "POST", "low", "Email/password login; 2FA shape unverified — prefer HTB_TOKEN."),
        "categories": Endpoint("/challenge/categories/list", "GET", "medium", "Challenge category id->name map."),
        "challenge_list": Endpoint("/challenge/list", "GET", "medium", "Active challenges; response shape parsed defensively."),
        "challenge_list_retired": Endpoint("/challenge/list/retired", "GET", "medium", "Retired challenges."),
        "challenge_info": Endpoint("/challenge/info/{challenge_id}", "GET", "medium", "Full challenge detail."),
        "challenge_download": Endpoint("/challenge/download/{challenge_id}", "GET", "medium", "Binary challenge archive."),
        # Container instance lifecycle. Confirmed from the HTB app frontend
        # (common-api chunk): POST /container/{start,stop} with body
        # {containerable_id: <challenge id>}.
        "challenge_start": Endpoint("/container/start", "POST", "high", "Spawn container; body {containerable_id}."),
        "challenge_stop": Endpoint("/container/stop", "POST", "high", "Stop container; body {containerable_id}."),
        # Flag submission ("own"). Never called without explicit --submit.
        # Verified live: a successful submission returns "Congratulations!".
        "challenge_own": Endpoint("/challenge/own", "POST", "high", "Submit flag; body {challenge_id, flag, difficulty}."),
    }


@dataclass
class HTBConfig:
    api_base: str = field(default_factory=lambda: os.getenv("HTB_API_BASE", DEFAULT_API_BASE).rstrip("/"))
    timeout_seconds: float = field(default_factory=lambda: _float_env("HTB_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS))
    user_agent: str = field(default_factory=lambda: os.getenv("HTB_USER_AGENT", DEFAULT_USER_AGENT))
    archive_password: str = field(default_factory=lambda: os.getenv("HTB_ARCHIVE_PASSWORD", DEFAULT_ARCHIVE_PASSWORD))
    spawn_timeout_seconds: float = field(default_factory=lambda: _float_env("HTB_SPAWN_TIMEOUT_SECONDS", DEFAULT_SPAWN_TIMEOUT_SECONDS))
    spawn_poll_seconds: float = field(default_factory=lambda: _float_env("HTB_SPAWN_POLL_SECONDS", DEFAULT_SPAWN_POLL_SECONDS))
    endpoints: Dict[str, Endpoint] = field(default_factory=_default_endpoints)

    def __post_init__(self) -> None:
        # Apply per-endpoint path overrides from the environment.
        for name, env_key in ENDPOINT_ENV_KEYS.items():
            override = os.getenv(env_key)
            if override:
                current = self.endpoints.get(name)
                method = current.method if current else "GET"
                self.endpoints[name] = Endpoint(override, method, "medium", f"Overridden via {env_key}.")

    def endpoint(self, name: str) -> Endpoint:
        try:
            return self.endpoints[name]
        except KeyError as exc:  # pragma: no cover - programmer error
            raise KeyError(f"Unknown HTB endpoint '{name}'") from exc


def _float_env(name: str, default: float) -> float:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return max(1.0, float(raw))
    except ValueError:
        return default

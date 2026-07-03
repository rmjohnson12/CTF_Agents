"""Authentication and session caching for Hack The Box.

Preferred path: an **App Token** (``HTB_TOKEN``) — HTB's supported programmatic
auth. Email/password login is a clearly-marked best-effort fallback; if 2FA is
required we fail with actionable guidance rather than inventing a 2FA endpoint
we cannot verify.

Sessions are cached in a git-ignored JSON file (default ``.htb_session.json``)
written with owner-only permissions. Only a token, the user profile, and a
timestamp are stored — never the password.
"""
from __future__ import annotations

import json
import logging
import os
import stat
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

from .client import HTBClient, redact_token
from .config import HTBConfig
from .errors import HTBAuthError, HTBError
from .models import HTBCredentials

logger = logging.getLogger(__name__)

DEFAULT_SESSION_FILE = ".htb_session.json"
# Treat a cached token older than this as stale and re-verify. (Verification is
# a live call regardless; this just avoids trusting very old files blindly.)
SESSION_MAX_AGE_SECONDS = 12 * 3600


@dataclass
class AuthResult:
    token: str
    user: Dict[str, Any]
    source: str  # "token" | "cache" | "login"

    def __repr__(self) -> str:
        return f"AuthResult(source={self.source}, token={redact_token(self.token)}, user_id={self.user.get('id')})"


class SessionCache:
    """Owner-only JSON cache of {token, user, obtained_at}."""

    def __init__(self, path: str = DEFAULT_SESSION_FILE):
        self.path = path

    def load(self) -> Optional[Dict[str, Any]]:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def save(self, token: str, user: Dict[str, Any]) -> None:
        payload = {"token": token, "user": user, "obtained_at": int(time.time())}
        try:
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except OSError as exc:  # pragma: no cover - best effort
            logger.warning("Could not write session cache %s: %s", self.path, exc)

    def clear(self) -> None:
        try:
            os.remove(self.path)
        except OSError:
            pass


def _verify_token(token: str, config: HTBConfig, session: Optional[requests.Session]) -> Dict[str, Any]:
    """Return the user profile for ``token`` or raise HTBAuthError."""
    client = HTBClient(token, config=config, session=session)
    return client.get_user_info()


def authenticate(
    creds: HTBCredentials,
    config: Optional[HTBConfig] = None,
    *,
    cache_path: str = DEFAULT_SESSION_FILE,
    session: Optional[requests.Session] = None,
    use_cache: bool = True,
    force_login: bool = False,
) -> AuthResult:
    """Authenticate, preferring token > cached session > email/password login."""
    config = config or HTBConfig()
    cache = SessionCache(cache_path)

    # 1) Explicit App Token wins.
    if creds.has_token and not force_login:
        user = _verify_token(creds.token, config, session)
        cache.save(creds.token, user)
        logger.info("Authenticated via HTB_TOKEN (user id=%s).", user.get("id"))
        return AuthResult(creds.token, user, "token")

    # 2) Cached session, re-verified against the API.
    if use_cache and not force_login:
        cached = cache.load()
        if cached and cached.get("token"):
            age = time.time() - float(cached.get("obtained_at", 0))
            if age <= SESSION_MAX_AGE_SECONDS:
                try:
                    user = _verify_token(cached["token"], config, session)
                    logger.info("Authenticated via cached session (user id=%s).", user.get("id"))
                    return AuthResult(cached["token"], user, "cache")
                except HTBError:
                    logger.info("Cached session invalid/expired; discarding.")
                    cache.clear()

    # 3) Email/password login (best-effort, low confidence).
    if creds.has_login:
        token = _login(creds, config, session)
        user = _verify_token(token, config, session)
        cache.save(token, user)
        logger.info("Authenticated via email/password login (user id=%s).", user.get("id"))
        return AuthResult(token, user, "login")

    raise HTBAuthError(
        "No usable credentials. Set HTB_TOKEN (recommended App Token) or "
        "HTB_EMAIL + HTB_PASSWORD in the environment."
    )


def _login(creds: HTBCredentials, config: HTBConfig, session: Optional[requests.Session]) -> str:
    """Best-effort email/password login. Returns a bearer token or raises.

    The login/2FA response shape is unverified in the community docs, so this
    parses defensively and, crucially, does NOT invent a 2FA endpoint: if 2FA is
    required we raise a clear error pointing at App Token auth.
    """
    http = session or requests.Session()
    endpoint = config.endpoint("login")
    url = f"{config.api_base}{endpoint.path}"
    try:
        resp = http.post(
            url,
            json={"email": creds.email, "password": creds.password, "remember": True},
            headers={"User-Agent": config.user_agent, "Accept": "application/json"},
            timeout=config.timeout_seconds,
        )
    except requests.RequestException as exc:
        raise HTBAuthError(f"Login request failed: {exc}") from exc

    if resp.status_code in (401, 403):
        raise HTBAuthError(
            "Login rejected (bad credentials or access denied). "
            "Do not retry in a loop — HTB login must not be brute-forced."
        )
    if resp.status_code >= 400:
        raise HTBAuthError(
            f"Login endpoint returned HTTP {resp.status_code}. The login flow may have "
            "changed; use an App Token via HTB_TOKEN instead."
        )

    try:
        data = resp.json()
    except ValueError:
        raise HTBAuthError("Login returned non-JSON; use an App Token via HTB_TOKEN instead.")

    if _requires_2fa(data):
        if not creds.otp:
            raise HTBAuthError(
                "This account requires 2FA. Provide HTB_OTP, or (recommended) use an "
                "App Token via HTB_TOKEN which is not subject to interactive 2FA."
            )
        # We will not guess an unverified 2FA verification endpoint. Fail clearly.
        raise HTBAuthError(
            "2FA verification over the API is not implemented against an unverified "
            "endpoint. Use an App Token via HTB_TOKEN (generated in HTB profile "
            "settings), which bypasses interactive 2FA safely."
        )

    token = _extract_token(data)
    if not token:
        raise HTBAuthError(
            "Login succeeded but no token was found in the response; the login shape "
            "may have changed. Use an App Token via HTB_TOKEN instead."
        )
    return token


def _requires_2fa(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    for key in ("requires_2fa", "two_factor", "2fa_required", "requires_otp"):
        if data.get(key):
            return True
    message = str(data.get("message", "")).lower()
    return "2fa" in message or "one time" in message or "otp" in message


def _extract_token(data: Any) -> Optional[str]:
    if not isinstance(data, dict):
        return None
    for key in ("access_token", "token", "api_token"):
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    message = data.get("message")
    if isinstance(message, dict):
        for key in ("access_token", "token"):
            value = message.get(key)
            if isinstance(value, str) and value:
                return value
    return None

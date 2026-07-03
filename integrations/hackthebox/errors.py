"""Typed exceptions for the Hack The Box integration.

Distinct types let the runner keep going on a per-challenge failure while still
distinguishing auth problems (abort the run) from a single unavailable
instance (skip and continue).
"""
from __future__ import annotations

from typing import Optional


class HTBError(Exception):
    """Base class for all Hack The Box integration errors."""


class HTBAuthError(HTBError):
    """Authentication/authorization failure (HTTP 401/403, bad/expired token).

    Raising this should abort the whole run: nothing else will succeed.
    """


class HTBRateLimitError(HTBError):
    """HTTP 429 / cooldown. Carries the server-advised retry delay when known."""

    def __init__(self, message: str, retry_after: Optional[float] = None):
        super().__init__(message)
        self.retry_after = retry_after


class HTBNotFoundError(HTBError):
    """HTTP 404 for a resource that legitimately may not exist (e.g. a challenge)."""


class HTBEndpointError(HTBError):
    """An endpoint responded in an unexpected way — likely the community-maintained
    path/shape has changed. Signals "verify against current docs", not a bug in
    the caller. Kept separate from HTBNotFoundError so the runner can surface a
    clear "the API may have changed" message instead of "challenge missing"."""


class HTBAPIError(HTBError):
    """Any other non-success API response with a captured status code."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code

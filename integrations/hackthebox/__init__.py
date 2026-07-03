"""Hack The Box challenge automation for a single authenticated account.

This package automates the *documented* Hack The Box v4 challenge workflow:
discover challenges, download files, (optionally) spawn instances, run the
existing CTF_Agents solver, and report candidate flags. It intentionally does
**not** submit flags unless the operator explicitly opts in.

Safety posture (enforced throughout the package):
  * Operates only on challenges the authenticated account can access.
  * Never targets non-HTB hosts; solver scope is limited to HTB-provided
    download artifacts and spawned instance targets.
  * Never brute-forces login, bypasses subscriptions/access controls, or
    scrapes private data.
  * Secrets come only from environment variables or a git-ignored session file;
    tokens/cookies are redacted in all logs and reports.

The public v4 API docs are community-maintained, so endpoints are treated as
*unverified until proven at runtime*: every call parses defensively and fails
cleanly (never crashes the whole run) if an endpoint has changed. See
``config.py`` for the endpoint table and per-endpoint confidence notes.
"""

from .errors import (
    HTBError,
    HTBAuthError,
    HTBRateLimitError,
    HTBNotFoundError,
    HTBEndpointError,
    HTBAPIError,
)
from .models import Challenge, SpawnInfo, ChallengeAttempt, RunReport, HTBCredentials

__all__ = [
    "HTBError",
    "HTBAuthError",
    "HTBRateLimitError",
    "HTBNotFoundError",
    "HTBEndpointError",
    "HTBAPIError",
    "Challenge",
    "SpawnInfo",
    "ChallengeAttempt",
    "RunReport",
    "HTBCredentials",
]

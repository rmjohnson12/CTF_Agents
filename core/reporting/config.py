"""Single source of truth for which environment variables hold reporting tokens.

The client, the API (``create_app``) and the ``reporting_server.py`` launcher all
resolve tokens through these functions, so they cannot drift apart on precedence.
"""

from __future__ import annotations

import os
from typing import Optional

WRITE_TOKEN_ENV = "CTF_AGENTS_REPORTING_WRITE_TOKEN"
READ_TOKEN_ENV = "CTF_AGENTS_REPORTING_READ_TOKEN"
# One token for both reads and writes, used when the specific one is unset.
SHARED_TOKEN_ENV = "CTF_AGENTS_REPORTING_API_TOKEN"
# Undocumented name only the client ever read; kept so existing setups keep working.
LEGACY_CLIENT_TOKEN_ENV = "CTF_AGENTS_REPORTING_TOKEN"


def _shared_token(shared: Optional[str]) -> Optional[str]:
    return shared if shared is not None else os.getenv(SHARED_TOKEN_ENV)


def resolve_write_token(
    explicit: Optional[str] = None,
    *,
    shared: Optional[str] = None,
) -> Optional[str]:
    """Token the server requires on POST: explicit > WRITE_TOKEN > shared (arg, else API_TOKEN)."""
    return explicit or os.getenv(WRITE_TOKEN_ENV) or _shared_token(shared) or None


def resolve_read_token(
    explicit: Optional[str] = None,
    *,
    shared: Optional[str] = None,
    write_token: Optional[str] = None,
) -> Optional[str]:
    """Token the server requires on GET: explicit > READ_TOKEN > shared > the write token."""
    return (
        explicit
        or os.getenv(READ_TOKEN_ENV)
        or _shared_token(shared)
        or write_token
        or None
    )


def resolve_client_token() -> Optional[str]:
    """Token the client sends on POST: the server's write token, then the legacy name."""
    return resolve_write_token() or os.getenv(LEGACY_CLIENT_TOKEN_ENV) or None

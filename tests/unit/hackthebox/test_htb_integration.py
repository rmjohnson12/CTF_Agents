"""Opt-in integration tests that hit the real HTB API (read-only).

These are skipped unless RUN_HTB_INTEGRATION_TESTS=1 and credentials are present
in the environment. They never spawn instances or submit flags — they only
authenticate and list challenges, which is safe, in-scope, and idempotent.
"""
import os

import pytest

from integrations.hackthebox.auth import authenticate
from integrations.hackthebox.client import HTBClient
from integrations.hackthebox.config import HTBConfig
from integrations.hackthebox.models import HTBCredentials

_ENABLED = os.getenv("RUN_HTB_INTEGRATION_TESTS") == "1"
_HAS_CREDS = bool(os.getenv("HTB_TOKEN") or (os.getenv("HTB_EMAIL") and os.getenv("HTB_PASSWORD")))

pytestmark = pytest.mark.skipif(
    not (_ENABLED and _HAS_CREDS),
    reason="Set RUN_HTB_INTEGRATION_TESTS=1 and HTB_TOKEN (or HTB_EMAIL/HTB_PASSWORD) to run.",
)


@pytest.fixture(scope="module")
def client():
    config = HTBConfig()
    auth = authenticate(HTBCredentials.from_env(), config)
    return HTBClient(auth.token, config=config)


def test_user_info(client):
    info = client.get_user_info()
    assert "id" in info


def test_list_challenges_readonly(client):
    challenges = client.list_challenges()
    assert isinstance(challenges, list)
    # Do not assert non-empty: account access may legitimately vary.
    for ch in challenges[:5]:
        assert ch.id and ch.name

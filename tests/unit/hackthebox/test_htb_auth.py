import json
import os
import stat
from pathlib import Path

import pytest

from integrations.hackthebox.auth import authenticate, SessionCache
from integrations.hackthebox.config import HTBConfig
from integrations.hackthebox.errors import HTBAuthError
from integrations.hackthebox.models import HTBCredentials
from htb_fakes import FakeResponse, FakeSession, route_handler


def test_token_auth_caches_session(tmp_path):
    session = FakeSession(route_handler({"/user/info": FakeResponse(200, {"info": {"id": 3, "name": "me"}})}))
    creds = HTBCredentials(token="app-token")
    cache_path = tmp_path / ".htb_session.json"

    result = authenticate(creds, HTBConfig(), cache_path=str(cache_path), session=session)

    assert result.source == "token"
    assert result.user["id"] == 3
    assert cache_path.exists()
    # cached file is owner-only and stores the token but never a password
    mode = stat.S_IMODE(os.stat(cache_path).st_mode)
    assert mode == 0o600
    cached = json.loads(cache_path.read_text())
    assert cached["token"] == "app-token"


def test_no_credentials_raises(tmp_path):
    with pytest.raises(HTBAuthError):
        authenticate(HTBCredentials(), HTBConfig(), cache_path=str(tmp_path / "s.json"), use_cache=False)


def test_cached_session_reused(tmp_path):
    cache_path = tmp_path / ".htb_session.json"
    SessionCache(str(cache_path)).save("cached-token", {"id": 9, "name": "cached"})
    session = FakeSession(route_handler({"/user/info": FakeResponse(200, {"info": {"id": 9, "name": "cached"}})}))

    result = authenticate(HTBCredentials(), HTBConfig(), cache_path=str(cache_path), session=session)

    assert result.source == "cache"
    assert result.user["id"] == 9


def test_login_requires_2fa_fails_clearly(tmp_path):
    session = FakeSession(route_handler({"/login": FakeResponse(200, {"message": "2FA required", "requires_2fa": True})}))
    creds = HTBCredentials(email="a@b.c", password="pw")  # no OTP

    with pytest.raises(HTBAuthError) as exc:
        authenticate(creds, HTBConfig(), cache_path=str(tmp_path / "s.json"), session=session, use_cache=False)
    assert "2FA" in str(exc.value) or "App Token" in str(exc.value)


def test_login_success_extracts_token(tmp_path):
    routes = {
        "/login": FakeResponse(200, {"message": {"token": "login-token"}}),
        "/user/info": FakeResponse(200, {"info": {"id": 1, "name": "u"}}),
    }
    session = FakeSession(route_handler(routes))
    creds = HTBCredentials(email="a@b.c", password="pw")

    result = authenticate(creds, HTBConfig(), cache_path=str(tmp_path / "s.json"), session=session, use_cache=False)
    assert result.source == "login"
    assert result.token == "login-token"


def test_bad_login_credentials_do_not_loop(tmp_path):
    session = FakeSession(route_handler({"/login": FakeResponse(401, {"message": "invalid"})}))
    creds = HTBCredentials(email="a@b.c", password="wrong")
    with pytest.raises(HTBAuthError):
        authenticate(creds, HTBConfig(), cache_path=str(tmp_path / "s.json"), session=session, use_cache=False)
    # exactly one login attempt was made (no brute-force retry loop)
    login_calls = [c for c in session.calls if c["url"].endswith("/login")]
    assert len(login_calls) == 1

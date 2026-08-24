from types import SimpleNamespace

import pytest

from core.utils.security import SecurityPolicyError, networks_from_challenge
from tools.web.http_fetch import HttpFetchTool


class DummyElapsed:
    def total_seconds(self) -> float:
        return 0.123


def test_http_fetch_truncates_body(monkeypatch):
    monkeypatch.setenv("CTF_AGENTS_ALLOWED_NETWORKS", "example.local")
    tool = HttpFetchTool(max_preview_chars=10)

    dummy_resp = SimpleNamespace(
        status_code=200,
        url="http://example.local/final",
        headers={"Content-Type": "text/plain"},
        text="abcdefghijklmnopqrstuvwxyz",
        elapsed=DummyElapsed(),
    )

    def fake_request(*args, **kwargs):
        return dummy_resp

    monkeypatch.setattr("requests.request", fake_request)

    res = tool.fetch("http://example.local/start")

    assert res.status_code == 200
    assert res.final_url.endswith("/final")
    assert res.headers["Content-Type"] == "text/plain"
    assert res.body_preview.startswith("abcdefghij")
    assert "[truncated]" in res.body_preview


def test_http_fetch_forwards_payload_options_and_captures_cookies(monkeypatch):
    monkeypatch.setenv("CTF_AGENTS_ALLOWED_NETWORKS", "example.local")
    tool = HttpFetchTool()
    captured = {}

    class DummyCookies:
        def get_dict(self):
            return {"session": "abc123"}

    dummy_resp = SimpleNamespace(
        status_code=201,
        url="http://example.local/api",
        headers={},
        text="ok",
        elapsed=DummyElapsed(),
        cookies=DummyCookies(),
    )

    def fake_request(*args, **kwargs):
        captured.update(kwargs)
        return dummy_resp

    monkeypatch.setattr("requests.request", fake_request)

    res = tool.fetch(
        "http://example.local/api",
        method="POST",
        headers={"Content-Type": "application/json"},
        data="raw",
        json_data={"role": "admin"},
        files={"upload": ("x.zip", b"data", "application/zip")},
        cookies={"session": "old"},
        params={"debug": "1"},
    )

    assert captured["method"] == "POST"
    assert captured["headers"] == {"Content-Type": "application/json"}
    assert captured["data"] == "raw"
    assert captured["json"] == {"role": "admin"}
    assert captured["files"]["upload"][0] == "x.zip"
    assert captured["cookies"] == {"session": "old"}
    assert captured["params"] == {"debug": "1"}
    assert res.cookies == {"session": "abc123"}


def test_http_fetch_blocks_non_allowlisted_host(monkeypatch):
    monkeypatch.setenv("CTF_AGENTS_ALLOWED_NETWORKS", "ctf.local")
    tool = HttpFetchTool()

    with pytest.raises(SecurityPolicyError):
        tool.fetch("http://evil.example/")


def test_http_fetch_blocks_redirect_to_non_allowlisted_host(monkeypatch):
    monkeypatch.setenv("CTF_AGENTS_ALLOWED_NETWORKS", "example.local")
    tool = HttpFetchTool()

    first_resp = SimpleNamespace(
        status_code=302,
        url="http://example.local/start",
        headers={"Location": "http://evil.example/"},
        text="",
        elapsed=DummyElapsed(),
        is_redirect=True,
    )

    def fake_request(*args, **kwargs):
        return first_resp

    monkeypatch.setattr("requests.request", fake_request)

    with pytest.raises(SecurityPolicyError):
        tool.fetch("http://example.local/start")


def test_networks_from_challenge_ignores_remote_hosts():
    challenge = {
        "url": "https://attacker.example",
        "target": {"url": "http://154.57.164.65:31327"},
        "connection_info": {"rpc_url": "http://127.0.0.1:8545"},
    }

    assert networks_from_challenge(challenge) == ["127.0.0.1"]

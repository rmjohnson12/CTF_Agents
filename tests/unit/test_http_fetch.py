from types import SimpleNamespace

from tools.web.http_fetch import HttpFetchTool


class DummyElapsed:
    def total_seconds(self) -> float:
        return 0.123


def test_http_fetch_truncates_body(monkeypatch):
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

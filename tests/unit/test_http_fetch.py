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
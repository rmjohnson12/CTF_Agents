"""Regression test for the general API command-enumeration web playbook.

Models the "Flag Command" class of challenge (discover a hidden option in an
API and submit it) without hard-coding the specific command, endpoint, or flag.
"""
import json

from tools.web.http_fetch import HttpFetchResult, HttpContentResult
from agents.specialists.web_exploitation.web_agent import WebExploitationAgent

FLAG = "HTB{secret_option_wins}"
SECRET_CMD = "Blip-blop, in a pickle"

_INDEX_HTML = '<html><script src="/static/main.js"></script></html>'
_MAIN_JS = (
    "async function go(){ await fetch('/api/options'); "
    "await fetch('/api/monitor', {method:'POST'}); }"
    # padding beyond the default 10k preview to prove full-content fetch is used
    + ("// filler\n" * 1500)
)
_OPTIONS = {
    "allPossibleCommands": {
        "1": ["HEAD NORTH", "HEAD SOUTH"],
        "secret": [SECRET_CMD],
    }
}


class _FakeHttp:
    """Fake HttpFetchTool covering fetch_content (GET) and fetch (POST)."""

    def fetch_content(self, url, **kw):
        if url.endswith("/"):
            body = _INDEX_HTML
        elif url.endswith("/static/main.js"):
            body = _MAIN_JS
        elif url.endswith("/api/options"):
            body = json.dumps(_OPTIONS)
        elif url.endswith("/api/monitor"):
            return HttpContentResult(url, url, "GET", 405, {}, b"method not allowed", 0.0)
        else:
            return HttpContentResult(url, url, "GET", 404, {}, b"", 0.0)
        return HttpContentResult(url, url, "GET", 200, {}, body.encode(), 0.0)

    def fetch(self, url, *, method="GET", json_data=None, **kw):
        if url.endswith("/api/monitor") and method == "POST":
            if (json_data or {}).get("command") == SECRET_CMD:
                return HttpFetchResult(url, url, "POST", 200, {}, json.dumps({"message": FLAG}), 0.0)
            return HttpFetchResult(url, url, "POST", 200, {}, json.dumps({"message": "wrong"}), 0.0)
        return HttpFetchResult(url, url, method, 404, {}, "", 0.0)


def test_api_command_enumeration_finds_hidden_option():
    agent = WebExploitationAgent(http_tool=_FakeHttp())
    steps = []
    flag = agent._try_api_command_enumeration("http://target:1234", steps)
    assert flag == FLAG
    assert any("SUCCESS" in s for s in steps)


def test_api_command_enumeration_returns_none_without_api():
    class _NoApi(_FakeHttp):
        def fetch_content(self, url, **kw):
            return HttpContentResult(url, url, "GET", 200, {}, b"<html>nothing here</html>", 0.0)

    agent = WebExploitationAgent(http_tool=_NoApi())
    assert agent._try_api_command_enumeration("http://target:1234", []) is None


def test_solve_challenge_uses_playbook_for_web_url():
    agent = WebExploitationAgent(http_tool=_FakeHttp())
    result = agent.solve_challenge({
        "id": "t", "name": "Flag Command", "category": "web",
        "description": "a game", "url": "http://target:1234", "files": [],
    })
    assert result["status"] == "solved"
    assert result["flag"] == FLAG

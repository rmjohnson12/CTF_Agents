import pytest
import json
from tools.web.browser_snapshot_tool import BrowserSnapshotResult
from tools.web.http_fetch import HttpFetchResult
from tools.web.sqlmap import SqlmapTool
from tools.web.dirsearch import DirsearchTool
from tools.web.react2shell import React2ShellResult, React2ShellTool
from tools.common.result import ToolResult
from agents.specialists.web_exploitation.web_agent import WebExploitationAgent

class MockRunner:
    def __init__(self, stdout):
        self.stdout = stdout
    def run(self, argv, timeout_s=None, cwd=None, env=None):
        return ToolResult(argv, self.stdout, "", 0, False, 0.1)

def test_sqlmap_vulnerable_parsing():
    stdout = "some noise... back-end DBMS: MySQL ... Payload: id=1 UNION SELECT ... is vulnerable"
    tool = SqlmapTool(runner=MockRunner(stdout))
    res = tool.run("http://test.local")
    assert res.vulnerable is True
    assert res.db_type == "MySQL"
    assert len(res.payloads) > 0

def test_dirsearch_parsing():
    stdout = """
[10:00:00] 200 -   1KB - /admin.php
[10:00:01] 404 -   0B  - /notfound
[10:00:02] 200 -   5KB - /config.txt
"""
    tool = DirsearchTool(runner=MockRunner(stdout))
    res = tool.run("http://test.local")
    assert len(res.entries) == 2
    assert res.entries[0].url == "/admin.php"
    assert res.entries[0].status == 200
    assert res.entries[1].url == "/config.txt"


class MockBrowserTool:
    def snapshot(self, url, cookies=None):
        return BrowserSnapshotResult(
            url=url,
            final_url=url,
            title="Help Desk",
            http_status=200,
            elapsed_s=0.1,
            links=[url.rstrip("/") + "/app.js"],
            forms=[],
            text_preview="Support tickets use JWT sessions.",
            html_content="<script src='/app.js'></script>",
            cookies=[],
            script_srcs=[url.rstrip("/") + "/app.js"],
            hidden_inputs=[],
            screenshot_path="",
            html_path="",
            json_path="",
        )


class MockHttpTool:
    def fetch(self, url, **kwargs):
        body = "const app = 'helpdesk';"
        status = 200 if url.endswith("/app.js") else 404
        return HttpFetchResult(url, url, "GET", status, {}, body, 0.1)


class NoopDirsearchTool:
    def run(self, url):
        raise RuntimeError("dirsearch unavailable")


class FakeReact2ShellTool:
    def __init__(self, flag="HTB{react_oops_solved}"):
        self.calls = []
        self.flag = flag

    def run(self, url, *, file_path="/app/flag.txt", timeout_s=15):
        self.calls.append((url, file_path))
        return React2ShellResult(url, 500, self.flag, f'digest":"{self.flag}"')


def test_web_agent_jwt_playbook_uses_challenge_description():
    class JwtAgent(WebExploitationAgent):
        def _handle_jwt_playbook(self, url, artifacts, steps):
            steps.append("  Mock JWT playbook executed.")
            return "HTB{jwt_secret_leak}"

    agent = JwtAgent(
        browser_tool=MockBrowserTool(),
        http_tool=MockHttpTool(),
        dirsearch_tool=NoopDirsearchTool(),
    )

    result = agent.solve_challenge({
        "id": "jwt_web",
        "category": "web",
        "description": "Help desk portal uses JWT tokens for session management.",
        "url": "http://127.0.0.1:30433",
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{jwt_secret_leak}"
    assert any("Executing JWT Playbook" in step for step in result["steps"])


def test_web_agent_normalizes_bare_ip_port_url():
    class RecordingBrowserTool(MockBrowserTool):
        def __init__(self):
            self.urls = []

        def snapshot(self, url, cookies=None):
            self.urls.append(url)
            return super().snapshot(url, cookies=cookies)

    browser = RecordingBrowserTool()
    agent = WebExploitationAgent(
        browser_tool=browser,
        http_tool=MockHttpTool(),
        dirsearch_tool=NoopDirsearchTool(),
    )

    agent.solve_challenge({
        "id": "bare_ip_web",
        "category": "web",
        "description": "Help desk portal",
        "url": "127.0.0.1:30433",
    })

    assert browser.urls[0] == "http://127.0.0.1:30433"


def test_web_agent_audits_local_next_react_source_for_react2shell(tmp_path):
    challenge_dir = tmp_path / "challenge"
    challenge_dir.mkdir()
    (challenge_dir / "package.json").write_text(json.dumps({
        "name": "react2shell",
        "dependencies": {
            "next": "16.0.6",
            "react": "^19",
            "react-dom": "^19",
        },
    }))

    agent = WebExploitationAgent(dirsearch_tool=NoopDirsearchTool())
    result = agent.solve_challenge({
        "id": "reactoops",
        "category": "web",
        "description": "ReactOOPS source review challenge with React Server Components.",
        "files": [str(challenge_dir)],
    })

    assert result["status"] == "attempted"
    assert "react2shell_rsc_rce" in result["vulnerabilities_found"]
    assert result["artifacts"]["source_audit"]["react2shell"]["next"] == "16.0.6"
    assert any("React2Shell" in step for step in result["steps"])


def test_web_agent_uses_react2shell_tool_for_local_vulnerable_source(tmp_path):
    challenge_dir = tmp_path / "challenge"
    challenge_dir.mkdir()
    (challenge_dir / "package.json").write_text(json.dumps({
        "name": "react2shell",
        "dependencies": {
            "next": "16.0.6",
            "react": "^19",
        },
    }))
    r2s = FakeReact2ShellTool()

    agent = WebExploitationAgent(
        browser_tool=MockBrowserTool(),
        http_tool=MockHttpTool(),
        dirsearch_tool=NoopDirsearchTool(),
        react2shell_tool=r2s,
    )

    result = agent.solve_challenge({
        "id": "reactoops_live",
        "category": "web",
        "description": "ReactOOPS Docker challenge with React Server Components.",
        "files": [str(challenge_dir)],
        "url": "http://127.0.0.1:3000",
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{react_oops_solved}"
    assert r2s.calls == [("http://127.0.0.1:3000", "/app/flag.txt")]
    assert "react2shell_attempt" in result["artifacts"]


def test_react2shell_tool_refuses_non_local_targets_by_default(monkeypatch):
    monkeypatch.delenv("CTF_AGENTS_ALLOW_REMOTE_R2S", raising=False)
    with pytest.raises(PermissionError):
        React2ShellTool().run("https://example.com")


def test_react2shell_tool_allows_remote_when_explicitly_enabled(monkeypatch):
    calls = []

    class FakeResponse:
        status_code = 500
        text = '1:E{"digest":"HTB{remote_flag}"}'

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse()

    monkeypatch.setenv("CTF_AGENTS_ALLOW_REMOTE_R2S", "1")
    monkeypatch.setattr("tools.web.react2shell.requests.post", fake_post)

    result = React2ShellTool().run("https://example.com")

    assert result.flag == "HTB{remote_flag}"
    assert calls[0][0] == "https://example.com/"
    assert calls[0][1]["headers"]["Next-Action"] == "x"

import pytest
from tools.web.browser_snapshot_tool import BrowserSnapshotResult
from tools.web.http_fetch import HttpFetchResult
from tools.web.sqlmap import SqlmapTool
from tools.web.dirsearch import DirsearchTool
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

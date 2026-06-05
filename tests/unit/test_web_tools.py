import pytest
import json
import base64
import struct
from tools.web.browser_snapshot_tool import BrowserSnapshotResult
from tools.web.http_fetch import HttpFetchResult
from tools.web.http_fetch import HttpContentResult
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

def test_dirsearch_parsing(monkeypatch):
    monkeypatch.setenv("CTF_AGENTS_ALLOWED_NETWORKS", "test.local")
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


def test_dirsearch_gobuster_fallback_uses_argv_not_shell(monkeypatch):
    monkeypatch.setenv("CTF_AGENTS_ALLOWED_NETWORKS", "test.local")
    monkeypatch.setattr(
        "shutil.which",
        lambda name: None if name == "dirsearch" else "/usr/bin/gobuster",
    )
    monkeypatch.setattr("os.path.exists", lambda path: True)
    tool = DirsearchTool()
    captured = {}

    def fake_run(argv, timeout_s=None, cwd=None, env=None):
        captured["argv"] = argv
        return ToolResult(argv, "/admin (Status: 200) [Size: 1]", "", 0, False, 0.1)

    monkeypatch.setattr(tool.runner, "run", fake_run)

    malicious_url = "http://test.local/?x=$(touch /tmp/pwned)"
    res = tool.run(malicious_url)

    assert captured["argv"][0] == "gobuster"
    assert captured["argv"][3] == malicious_url
    assert len(res.entries) == 1


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
            local_storage={},
            session_storage={},
            screenshot_path="",
            html_path="",
            json_path="",
        )


class MockHttpTool:
    def fetch(self, url, **kwargs):
        body = "const app = 'helpdesk';"
        status = 200 if url.endswith("/app.js") else 404
        return HttpFetchResult(url, url, "GET", status, {}, body, 0.1)

    def fetch_content(self, url, **kwargs):
        return HttpContentResult(url, url, "GET", 404, {}, b"", 0.1)


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


def test_web_agent_does_not_persist_browser_session_state_by_default(monkeypatch):
    monkeypatch.delenv("CTF_AGENTS_CAPTURE_SENSITIVE_ARTIFACTS", raising=False)

    class SensitiveBrowserTool(MockBrowserTool):
        def snapshot(self, url, cookies=None):
            res = super().snapshot(url, cookies=cookies)
            res.cookies = [{"name": "session", "value": "secret-cookie"}]
            res.local_storage = {"jwt": "secret-jwt"}
            res.session_storage = {"csrf": "secret-csrf"}
            return res

    agent = WebExploitationAgent(
        browser_tool=SensitiveBrowserTool(),
        http_tool=MockHttpTool(),
        dirsearch_tool=NoopDirsearchTool(),
    )

    result = agent.solve_challenge({
        "id": "session_artifacts",
        "category": "web",
        "description": "Inspect this page.",
        "url": "http://127.0.0.1:30433",
    })

    snapshot = result["artifacts"]["browser_snapshot"]
    assert "cookies" not in snapshot
    assert "local_storage" not in snapshot
    assert "session_storage" not in snapshot


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


def test_web_agent_uses_json_length_coercion_palindrome_bypass(tmp_path):
    challenge_dir = tmp_path / "challenge"
    app_dir = challenge_dir / "app"
    app_dir.mkdir(parents=True)
    (challenge_dir / "flag.txt").write_text("HTB{FAKE_FLAG_FOR_TESTING}")
    (app_dir / "index.mjs").write_text("""
const IsPalinDrome = (string) => {
  if (string.length < 1000) return 'Tootus Shortus';
  for (const i of Array(string.length).keys()) {
    if (string[i] !== string[string.length - i - 1]) return 'Nope';
  }
}
app.post('/', async (c) => {
  const {palindrome} = await c.req.json();
});
""")

    class PalindromeHttpTool:
        def __init__(self):
            self.calls = []

        def fetch(self, url, **kwargs):
            self.calls.append((url, kwargs))
            if kwargs.get("method") == "POST" and kwargs.get("json_data") == {
                "palindrome": {"0": "x", "999": "x", "length": "1000"}
            }:
                return HttpFetchResult(url, url, "POST", 200, {}, "Hii Harry!!! HTB{real_remote_flag}", 0.1)
            return HttpFetchResult(url, url, "GET", 404, {}, "", 0.1)

    http = PalindromeHttpTool()
    agent = WebExploitationAgent(
        browser_tool=MockBrowserTool(),
        http_tool=http,
        dirsearch_tool=NoopDirsearchTool(),
    )

    result = agent.solve_challenge({
        "id": "magical_palindrome",
        "category": "web",
        "description": "JSON palindrome challenge.",
        "files": [str(challenge_dir)],
        "url": "http://127.0.0.1:31049",
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{real_remote_flag}"
    assert "json_length_coercion_palindrome" in result["vulnerabilities_found"]
    assert result["flag"] != "HTB{FAKE_FLAG_FOR_TESTING}"


def test_web_agent_solves_prime_product_code_runner():
    class PrimeRunnerHttpTool:
        def __init__(self):
            self.calls = []

        def fetch(self, url, **kwargs):
            self.calls.append((url, kwargs))
            if url.endswith("/run") and kwargs.get("method") == "POST":
                return HttpFetchResult(
                    url,
                    url,
                    "POST",
                    200,
                    {},
                    '{"flag":"HTB{prime_runner}","input":"4 7 9 11","result":"77\\n","stderr":""}',
                    0.1,
                )
            return HttpFetchResult(url, url, "GET", 404, {}, "", 0.1)

    http = PrimeRunnerHttpTool()
    agent = WebExploitationAgent(
        browser_tool=MockBrowserTool(),
        http_tool=http,
        dirsearch_tool=NoopDirsearchTool(),
    )

    result = agent.solve_challenge({
        "id": "primed_for_action",
        "category": "web",
        "description": "A list of numbers contains two primes. The key is the product of the two prime numbers.",
        "url": "http://127.0.0.1:30498",
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{prime_runner}"
    assert "coding_runner_prime_product" in result["vulnerabilities_found"]
    assert http.calls[0][0] == "http://127.0.0.1:30498/run"


def test_web_agent_follows_header_archived_path_and_decodes_certutil_block():
    class HeaderArtifactHttpTool:
        def __init__(self):
            self.fetches = []
            self.content_fetches = []

        def fetch(self, url, **kwargs):
            self.fetches.append(url)
            return HttpFetchResult(
                url,
                url,
                "GET",
                200,
                {
                    "X-Archived-Path": "/assets_production_system_v3/bak/file_backup.sys",
                    "X-Administrator-Note": "Structural certutil backup blocks retained.",
                },
                "<html>asset portal</html>",
                0.1,
            )

        def fetch_content(self, url, **kwargs):
            self.content_fetches.append(url)
            encoded = base64.b64encode(b"SVIBGR{header_artifact_pipeline}").decode()
            body = f"-----BEGIN CERTIFICATE-----\n{encoded}\n-----END CERTIFICATE-----\n".encode()
            return HttpContentResult(url, url, "GET", 200, {"Content-Type": "application/octet-stream"}, body, 0.1)

    http = HeaderArtifactHttpTool()
    agent = WebExploitationAgent(
        browser_tool=MockBrowserTool(),
        http_tool=http,
        dirsearch_tool=NoopDirsearchTool(),
    )

    result = agent.solve_challenge({
        "id": "header_backup",
        "category": "web",
        "description": "Public status page leaked a backup path.",
        "url": "https://example.test",
    })

    assert result["status"] == "solved"
    assert result["flag"] == "SVIBGR{header_artifact_pipeline}"
    assert http.content_fetches == ["https://example.test/assets_production_system_v3/bak/file_backup.sys"]
    assert any("Decoded certutil/PEM-style block" in step for step in result["steps"])


def test_web_agent_renders_binary_stl_header_artifact(tmp_path, monkeypatch):
    class HeaderStlHttpTool:
        def fetch(self, url, **kwargs):
            return HttpFetchResult(
                url,
                url,
                "GET",
                200,
                {"X-Archived-Path": "/bak/model.sys"},
                "",
                0.1,
            )

        def fetch_content(self, url, **kwargs):
            header = b"OpenSCAD Model".ljust(80, b"\x00")
            triangles = struct.pack("<I", 1)
            tri = struct.pack(
                "<12fH",
                0.0, 0.0, 1.0,
                0.0, 0.0, 3.0,
                1.0, 0.0, 3.0,
                0.0, 1.0, 3.0,
                0,
            )
            return HttpContentResult(url, url, "GET", 200, {"Content-Type": "application/octet-stream"}, header + triangles + tri, 0.1)

    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    original_import = __import__

    def import_without_matplotlib(name, *args, **kwargs):
        if name == "matplotlib" or name.startswith("matplotlib."):
            raise ImportError("matplotlib intentionally unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", import_without_matplotlib)
    agent = WebExploitationAgent(
        browser_tool=MockBrowserTool(),
        http_tool=HeaderStlHttpTool(),
        dirsearch_tool=NoopDirsearchTool(),
    )

    result = agent.solve_challenge({
        "id": "stl_header",
        "category": "web",
        "description": "Public page leaked an OpenSCAD backup.",
        "url": "https://example.test",
    })

    findings = result["artifacts"]["header_artifacts"][0]["findings"]
    stl = next(item for item in findings if item["type"] == "binary_stl")

    assert result["status"] == "attempted"
    assert stl["rendered_projection"]
    assert stl["rendered_projection"].endswith("stl_header_stl_projection.svg")
    assert any("Detected binary STL artifact" in step for step in result["steps"])


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

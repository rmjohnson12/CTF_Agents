import pytest
import json
import base64
import io
import struct
import zipfile
from urllib.parse import parse_qsl, urlsplit
from tools.web.browser_snapshot_tool import BrowserSnapshotResult
from tools.web.http_fetch import HttpFetchResult
from tools.web.http_fetch import HttpContentResult
from tools.web.sqlmap import SqlmapTool
from tools.web.dirsearch import DirsearchTool
from tools.web.react2shell import React2ShellResult, React2ShellTool
from tools.common.result import ToolResult
from agents.specialists.web_exploitation.web_agent import WebExploitationAgent


def test_url_to_pdf_cross_parser_chain_preserves_duplicates_and_forges_jwt(monkeypatch):
    class FakeHttp:
        def __init__(self):
            self.urls = []

        def fetch_content(self, url, **kwargs):
            self.urls.append(url)
            return HttpContentResult(
                url=url,
                final_url="http://target/pdfs/result.pdf",
                method="GET",
                status_code=200,
                headers={"Content-Type": "application/pdf"},
                content=b"%PDF-stage",
                elapsed_s=0.1,
            )

    html = """
      <input id="url-input"><input id="name-input"><input id="secret-input">
      <script>
      const params = new URLSearchParams({ url: urlValue, secret: secretValue, name: nameValue });
      fetch('/bartender.php?' + params).then(res => res.blob());
      const filename = 'PEEK.pdf';
      </script>
    """
    http = FakeHttp()
    agent = WebExploitationAgent(http_tool=http)
    secret = "a" * 64
    extracted = iter(["seeded", f"history signing key {secret}", "HTB{cross_parser_proof}"])
    monkeypatch.setattr(agent, "_extract_pdf_text", lambda _content: next(extracted))
    steps, artifacts = [], {}

    flag = agent._try_url_to_pdf_cross_parser_chain(
        "http://target/",
        html,
        steps,
        artifacts,
    )

    assert flag == "HTB{cross_parser_proof}"
    assert len(http.urls) == 3
    first_pairs = parse_qsl(urlsplit(http.urls[0]).query)
    assert first_pairs[0][0] == first_pairs[1][0] == "url"
    assert first_pairs[0][1].startswith("http://127.0.0.1:5000/")
    assert first_pairs[1] == ("url", "http://example.com/")
    final_internal = parse_qsl(urlsplit(http.urls[-1]).query)[0][1]
    assert final_internal.startswith("http://127.0.0.1:5000/bartender?token=")
    token = final_internal.split("token=", 1)[1]
    _header, payload = agent._decode_jwt(token)
    assert payload == {"username": "admin", "is_admin": True}
    assert artifacts["cross_parser_pdf_chain"]["captured_sensitive_values"] is False


def test_url_to_pdf_chain_requires_complete_runtime_fingerprint():
    agent = WebExploitationAgent()

    assert agent._try_url_to_pdf_cross_parser_chain(
        "http://target/", "<input name='url'>", [], {}
    ) is None

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

    assert result["status"] == "solved", result["steps"]
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


def test_web_agent_extracts_stl_projection_flag_with_macos_vision(tmp_path, monkeypatch):
    image = tmp_path / "projection.png"
    image.write_bytes(b"not really an image; subprocess is mocked")
    agent = WebExploitationAgent()
    steps = []

    monkeypatch.setattr("agents.specialists.web_exploitation.web_agent.shutil.which", lambda name: "/usr/bin/swift")

    def fake_run(argv, **kwargs):
        assert argv[0] == "swift"
        assert argv[2] == str(image)
        return type("RunResult", (), {
            "returncode": 0,
            "stdout": "SVIBGR{n3v3r_d1sm1ss_th3_f1n3_4rts}\n",
            "stderr": "",
        })()

    monkeypatch.setattr("agents.specialists.web_exploitation.web_agent.subprocess.run", fake_run)

    flag = agent._extract_flag_from_projection_with_macos_vision(str(image), steps)

    assert flag == "SVIBGR{n3v3r_d1sm1ss_th3_f1n3_4rts}"
    assert any("Vision OCR recovered flag" in step for step in steps)


def test_web_agent_normalizes_stl_ocr_line_breaks_inside_flag():
    text = "SVIBGR{n3v3r_d1sm1ss_th3_f1n3\n4rts}"

    assert (
        WebExploitationAgent._find_flag_in_ocr_text(text)
        == "SVIBGR{n3v3r_d1sm1ss_th3_f1n3_4rts}"
    )


def test_web_agent_solves_leaked_jwt_comment_chat_api():
    class ClippyHttpTool:
        def __init__(self):
            self.posts = []
            self.base_token = WebExploitationAgent()._encode_hs256_jwt(
                {"role": "user", "ai_mode": "safe"},
                "not-the-real-secret",
            )

        def fetch(self, url, **kwargs):
            method = kwargs.get("method", "GET")
            if method == "POST" and url.endswith("/api/chat"):
                self.posts.append((url, kwargs))
                token = kwargs.get("cookies", {}).get("clippygpt_session", "")
                _header, payload = WebExploitationAgent()._decode_jwt(token)
                message = kwargs.get("json_data", {}).get("message")
                if (
                    payload
                    and payload.get("role") == "admin"
                    and payload.get("ai_mode") == "debug"
                    and message == "!get_flag"
                ):
                    return HttpFetchResult(
                        url,
                        url,
                        "POST",
                        200,
                        {},
                        '{"reply":"SVIBGR{jw7_4i_7rus7_issu3}"}',
                        0.1,
                    )
                return HttpFetchResult(url, url, "POST", 403, {}, '{"reply":"denied"}', 0.1)

            if url.endswith("/static/app.js"):
                return HttpFetchResult(
                    url,
                    url,
                    "GET",
                    200,
                    {},
                    'async function chat(message){ return fetch("/api/chat", {method:"POST"}); }',
                    0.1,
                )

            body = """
                <html>
                  <script src="/static/app.js"></script>
                  <!-- TODO: use 'cl1ppy123!!!' as signing key and change ai_mode to 'debug' for internal testing. -->
                </html>
            """
            return HttpFetchResult(
                url,
                url,
                "GET",
                200,
                {"Set-Cookie": f"clippygpt_session={self.base_token}; Path=/; HttpOnly"},
                body,
                0.1,
                {"clippygpt_session": self.base_token},
            )

        def fetch_content(self, url, **kwargs):
            return HttpContentResult(url, url, "GET", 404, {}, b"", 0.1)

    http = ClippyHttpTool()
    class FailingBrowserTool(MockBrowserTool):
        def snapshot(self, url, cookies=None):
            raise AssertionError("JWT source solve should return before browser snapshot")

    agent = WebExploitationAgent(
        browser_tool=FailingBrowserTool(),
        http_tool=http,
        dirsearch_tool=NoopDirsearchTool(),
    )

    result = agent.solve_challenge({
        "id": "clippygpt",
        "category": "web",
        "description": "ClippyGPT web challenge",
        "url": "https://clippy.test",
    })

    assert result["status"] == "solved"
    assert result["flag"] == "SVIBGR{jw7_4i_7rus7_issu3}"
    assert any("JWT source playbook SUCCESS" in step for step in result["steps"])
    assert result["artifacts"]["jwt_source_playbook"]["captured_sensitive_values"] is False
    assert "cl1ppy123!!!" not in json.dumps(result["artifacts"])
    assert not any("cl1ppy123!!!" in step for step in result["steps"])
    assert http.posts


def test_web_agent_solves_mongoose_socket_prototype_pollution_from_source(tmp_path):
    source_dir = tmp_path / "secure_notes"
    source_dir.mkdir()
    (source_dir / "package.json").write_text(
        json.dumps({"dependencies": {"express": "^4.18.2", "mongoose": "^7.2.4"}}),
        encoding="utf-8",
    )
    (source_dir / "app.js").write_text(
        '''
const express = require('express');
const app = express();
app.get('/flag', (req, res) => {
  if (req.connection.remoteAddress === '127.0.0.1') res.send(process.env.FLAG);
  else res.status(403).send('denied');
});
app.post('/create', async (req, res) => res.json(await Note.create(req.body)));
app.post('/update', async (req, res) => {
  await Note.findByIdAndUpdate(req.body.noteId, req.body);
  res.json({ok: true});
});
app.get('/get/:noteId', async (req, res) => res.json(await Note.findOne({_id: req.params.noteId})));
''',
        encoding="utf-8",
    )

    class SecureNotesHttpTool:
        def __init__(self):
            self.calls = []

        def fetch(self, url, **kwargs):
            self.calls.append((url, kwargs))
            path = url.replace("https://notes.test", "")
            if path == "/create":
                assert kwargs["json_data"]["title"] == "127.0.0.1"
                body = '{"_id":"507f1f77bcf86cd799439011"}'
            elif path == "/update":
                assert kwargs["json_data"]["$rename"] == {
                    "title": "__proto__._peername.address"
                }
                body = '{"ok":true}'
            elif path == "/get/507f1f77bcf86cd799439011":
                body = '{"content":"probe"}'
            elif path == "/flag":
                body = 'HTB{mongoose_internal_socket}'
            else:
                raise AssertionError(f"unexpected request: {url}")
            return HttpFetchResult(url, url, kwargs.get("method", "GET"), 200, {}, body, 0.1)

        def fetch_content(self, url, **kwargs):
            return HttpContentResult(url, url, "GET", 404, {}, b"", 0.1)

    class FailingBrowserTool(MockBrowserTool):
        def snapshot(self, url, cookies=None):
            raise AssertionError("source-guided Mongoose playbook should run before browser recon")

    http = SecureNotesHttpTool()
    agent = WebExploitationAgent(
        browser_tool=FailingBrowserTool(),
        http_tool=http,
        dirsearch_tool=NoopDirsearchTool(),
    )
    result = agent.solve_challenge({
        "id": "secure_notes",
        "category": "web",
        "description": "Only those who knock from inside may enter.",
        "url": "https://notes.test",
        "files": [str(source_dir)],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{mongoose_internal_socket}"
    assert any("prototype-pollution playbook SUCCESS" in step for step in result["steps"])
    assert result["artifacts"]["mongoose_prototype_pollution_attempt"]["captured_sensitive_values"] is False


def test_web_agent_solves_predictable_file_session_archive_chain():
    base = "https://desires.test"

    class DesiresHttpTool:
        def __init__(self):
            self.upload_members = []
            self.failed_victim_login = False

        def fetch(self, url, **kwargs):
            path = url.replace(base, "") or "/"
            method = kwargs.get("method", "GET")
            if path == "/" and method == "GET":
                body = '''
                <title>Login | Desires</title>
                <form action="/login" method="POST"></form>
                <a href="/register">Register here</a>
                '''
                return HttpFetchResult(url, url, method, 200, {"Date": "Thu, 01 Jan 1970 00:00:01 GMT"}, body, 0.1)
            if path == "/register" and method == "POST":
                return HttpFetchResult(url, url, method, 302, {"Location": "/"}, "", 0.1)
            if path == "/login" and method == "POST":
                password = kwargs["json_data"]["password"]
                if password == "intentionally-wrong":
                    self.failed_victim_login = True
                    return HttpFetchResult(url, url, method, 400, {}, '{"error":"invalid"}', 0.1)
                return HttpFetchResult(
                    url, url, method, 302, {"Location": "/user/upload"}, "", 0.1,
                    {"session": "attacker-session", "username": kwargs["json_data"]["username"]},
                )
            if path == "/user/upload" and method == "GET":
                assert kwargs["cookies"]["session"] == "attacker-session"
                body = '<form enctype="multipart/form-data"><input name="archive" type="file"></form>'
                return HttpFetchResult(url, url, method, 200, {}, body, 0.1)
            if path == "/user/upload" and method == "POST":
                archive_bytes = kwargs["files"]["archive"][1]
                with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
                    self.upload_members = archive.namelist()
                    assert archive.read("sessions") == b"/tmp/sessions"
                return HttpFetchResult(url, url, method, 202, {}, '{"message":"ok"}', 0.1)
            if path == "/user/admin":
                assert self.failed_victim_login
                assert kwargs["cookies"]["session"]
                return HttpFetchResult(url, url, method, 200, {}, "HTB{desires_session_chain}", 0.1)
            if method == "GET":
                return HttpFetchResult(url, url, method, 404, {}, "not found", 0.1)
            raise AssertionError(f"unexpected request: {method} {url}")

        def fetch_content(self, url, **kwargs):
            return HttpContentResult(url, url, "GET", 404, {}, b"", 0.1)

    class FailingBrowserTool(MockBrowserTool):
        def snapshot(self, url, cookies=None):
            raise AssertionError("predictable-session playbook should run before browser recon")

    http = DesiresHttpTool()
    result = WebExploitationAgent(
        browser_tool=FailingBrowserTool(),
        http_tool=http,
        dirsearch_tool=NoopDirsearchTool(),
    ).solve_challenge({
        "id": "desires",
        "category": "web",
        "description": "Survivors face the vault as toxic gas fuels greed.",
        "url": base,
    })

    assert result["status"] == "solved", result["steps"]
    assert result["flag"] == "HTB{desires_session_chain}"
    assert any(name.startswith("sessions/ctf_victim_") for name in http.upload_members)
    assert any("Predictable-session archive playbook SUCCESS" in step for step in result["steps"])
    assert result["artifacts"]["predictable_session_archive"]["captured_sensitive_values"] is False


def test_web_agent_solves_client_side_hash_auth_impersonation():
    base = "https://intern-net.test"
    normal_hash = "$2b$12$normalnormalnormalnormalnormalnormalnormalnormalnormalno"
    senior_hash = "$2b$12$seniorseniorseniorseniorseniorseniorseniorseniorsenio"
    normal_cookie = base64.b64encode(normal_hash.encode()).decode()
    senior_cookie = base64.b64encode(senior_hash.encode()).decode()

    class InternNetHttpTool:
        def fetch(self, url, **kwargs):
            method = kwargs.get("method", "GET")
            json_data = kwargs.get("json_data") or {}
            cookies = kwargs.get("cookies") or {}
            path = url.replace(base, "")

            if path in ("", "/", "/login"):
                body = """
                <form id="login-form"></form>
                <script src="/static/js/login.js"></script>
                """
                return HttpFetchResult(url, url, method, 200, {}, body, 0.1)
            if path == "/static/js/login.js":
                body = """
                const hashRes = await fetch('/api/auth/hash', {method: 'POST'});
                const isValid = await bcrypt.compare(password, hash);
                const token = btoa(hash);
                document.cookie = `auth_token=${token}; path=/; SameSite=Lax`;
                window.location.href = '/announcements';
                """
                return HttpFetchResult(url, url, method, 200, {}, body, 0.1)
            if path == "/api/register":
                return HttpFetchResult(url, url, method, 200, {}, '{"success":true}', 0.1)
            if path == "/api/auth/hash":
                username = json_data.get("username")
                if username and username.startswith("ctfagent_"):
                    return HttpFetchResult(url, url, method, 200, {}, json.dumps({"hash": normal_hash}), 0.1)
                if username == "alex.rivera":
                    return HttpFetchResult(url, url, method, 200, {}, json.dumps({"hash": senior_hash}), 0.1)
                return HttpFetchResult(url, url, method, 404, {}, '{"error":"User not found"}', 0.1)
            if path == "/announcements":
                if cookies.get("auth_token") == senior_cookie:
                    body = "<span>Signed in as <strong>Alex Rivera</strong></span> SVIUSCG{hash_auth_solved}"
                elif cookies.get("auth_token") == normal_cookie:
                    body = """
                    <span class="post-author">Alex Rivera</span>
                    <span class="badge badge-senior">Senior Intern</span>
                    <div class="locked-notice">Restricted to Senior Interns only.</div>
                    """
                else:
                    body = "<a href='/login'>login</a>"
                return HttpFetchResult(url, url, method, 200, {}, body, 0.1)
            return HttpFetchResult(url, url, method, 404, {}, "not found", 0.1)

        def fetch_content(self, url, **kwargs):
            return HttpContentResult(url, url, "GET", 404, {}, b"", 0.1)

    class FailBrowser:
        def snapshot(self, url, cookies=None):
            raise AssertionError("hash-auth playbook should return before browser snapshot")

    agent = WebExploitationAgent(
        http_tool=InternNetHttpTool(),
        browser_tool=FailBrowser(),
        dirsearch_tool=NoopDirsearchTool(),
    )
    result = agent.solve_challenge({
        "id": "intern_net",
        "category": "web",
        "url": base,
        "description": "Intern portal web challenge.",
        "files": [],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "SVIUSCG{hash_auth_solved}"
    assert any("Hash-auth playbook SUCCESS" in step for step in result["steps"])
    assert result["artifacts"]["client_side_hash_auth"]["captured_sensitive_values"] is False


def test_web_agent_solves_source_guided_public_incident_filter(tmp_path):
    source_dir = tmp_path / "incidental"
    source_dir.mkdir()
    (source_dir / "app.py").write_text(
        '''
from flask import Flask, jsonify, request
app = Flask(__name__)

@app.get("/api/incidents")
def api_incidents():
    v = request.args.get("public")
    if v is None:
        selected = data
    elif v.lower() in {"1", "true", "yes"}:
        selected = [i for i in data if i["public"]]
    elif v.lower() in {"0", "false", "no"}:
        selected = [i for i in data if not i["public"]]
    return jsonify({"incidents": selected})
''',
        encoding="utf-8",
    )
    static_dir = source_dir / "static"
    static_dir.mkdir()
    (static_dir / "status-page.js").write_text(
        'async function boot(){ return fetch("/api/incidents?public=1"); }',
        encoding="utf-8",
    )

    class IncidentHttpTool:
        def __init__(self):
            self.urls = []

        def fetch(self, url, **kwargs):
            self.urls.append(url)
            body = '{"incidents":[]}'
            if url.endswith("/api/incidents?public=0"):
                body = '{"body":"Action item tracking token: SVIBGR{pr073c7_y0ur_s747us_p4g3s}"}'
            return HttpFetchResult(url, url, "GET", 200, {}, body, 0.1)

        def fetch_content(self, url, **kwargs):
            return HttpContentResult(url, url, "GET", 404, {}, b"", 0.1)

    class FailingBrowserTool(MockBrowserTool):
        def snapshot(self, url, cookies=None):
            raise AssertionError("source-guided API probe should return before browser snapshot")

    http = IncidentHttpTool()
    agent = WebExploitationAgent(
        browser_tool=FailingBrowserTool(),
        http_tool=http,
        dirsearch_tool=NoopDirsearchTool(),
    )

    result = agent.solve_challenge({
        "id": "incidental",
        "category": "web",
        "description": "Public status page has internal incident feed data nearby.",
        "url": "https://status.test",
        "files": [str(source_dir)],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "SVIBGR{pr073c7_y0ur_s747us_p4g3s}"
    assert "https://status.test/api/incidents?public=0" in http.urls
    assert any("Source-guided API probe SUCCESS" in step for step in result["steps"])
    assert result["artifacts"]["source_api_param_probe"]["captured_sensitive_values"] is False


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


def test_react2shell_tool_allows_explicitly_allowlisted_remote(monkeypatch):
    calls = []

    class FakeResponse:
        status_code = 500
        text = '1:E{"digest":"HTB{allowlisted_remote}"}'

    monkeypatch.delenv("CTF_AGENTS_ALLOW_REMOTE_R2S", raising=False)
    monkeypatch.setenv("CTF_AGENTS_ALLOWED_NETWORKS", "192.0.2.10/32")
    monkeypatch.setattr("tools.web.react2shell.requests.post", lambda url, **kwargs: calls.append(url) or FakeResponse())

    result = React2ShellTool().run("http://192.0.2.10:31337")

    assert result.flag == "HTB{allowlisted_remote}"
    assert calls == ["http://192.0.2.10:31337/"]

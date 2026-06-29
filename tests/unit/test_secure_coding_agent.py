import json
from types import SimpleNamespace

from agents.specialists.secure_coding.secure_coding_agent import SecureCodingAgent


class FakeHttpTool:
    def __init__(self, verify_bodies, source_body=None):
        self.verify_bodies = list(verify_bodies)
        self.source_body = source_body
        self.saved = []
        self.calls = []

    def fetch(self, url, *, method="GET", params=None, json_data=None, **kwargs):
        self.calls.append((method, url, params, json_data))
        if url.rstrip("/").endswith("31337"):
            return SimpleNamespace(status_code=200, body_preview="not a coding runner")
        if url.endswith("/api/verify"):
            body = self.verify_bodies.pop(0)
            return SimpleNamespace(status_code=200, body_preview=body)
        if url.endswith("/api/file"):
            return SimpleNamespace(status_code=200, body_preview=self.source_body)
        if url.endswith("/api/save"):
            self.saved.append(json_data)
            return SimpleNamespace(status_code=200, body_preview='{"ok":true}')
        raise AssertionError(f"Unexpected URL: {url}")


def test_secure_coding_agent_accepts_verify_first_flag():
    http_tool = FakeHttpTool(['{"flag":"HTB{already_fixed_1234}"}'])
    agent = SecureCodingAgent(http_tool=http_tool)

    result = agent.solve_challenge({
        "id": "secure_001",
        "category": "secure_coding",
        "url": "http://127.0.0.1:31337",
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{already_fixed_1234}"
    assert result["artifacts"]["patch_applied"] is False
    assert not http_tool.saved


def test_secure_coding_agent_patches_legacy_flat_file_add_user():
    source = """export function addUser(username, password, role = 'operator') {
    const hashed = hashPassword(password);
    users.push(`${username}|${hashed}|${role}`);
    return true;
}
"""
    http_tool = FakeHttpTool(
        ['{"ok":false}', '{"flag":"HTB{patched_source_1234}"}'],
        source_body=json.dumps({"content": source}),
    )
    agent = SecureCodingAgent(http_tool=http_tool)

    result = agent.solve_challenge({
        "id": "secure_002",
        "category": "secure_coding",
        "url": "http://127.0.0.1:31337",
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{patched_source_1234}"
    assert result["artifacts"]["patch_applied"] is True
    assert len(http_tool.saved) == 1
    saved = http_tool.saved[0]
    assert saved["path"] == "utils/db.js"
    assert "username.includes('\\n')" in saved["content"]
    assert "username.includes('\\r')" in saved["content"]
    assert "username.includes('|')" in saved["content"]


def test_secure_coding_agent_solves_pin_enumeration_runner():
    class PinRunnerHttpTool:
        def __init__(self):
            self.submission = None

        def fetch(self, url, *, method="GET", json_data=None, **kwargs):
            if url.rstrip("/") == "http://127.0.0.1:30514":
                return SimpleNamespace(status_code=200, body_preview='''
                    Unknown positions are represented by "*".
                    No two adjacent digits can be the same.
                    <script>fetch("/run", {method: "POST"})</script>
                ''')
            if url.endswith("/run"):
                self.submission = json_data
                return SimpleNamespace(
                    status_code=200,
                    body_preview='{"challengeCompleted":true,"flag":"HTB{pin_runner_1234}"}',
                )
            raise AssertionError(f"Unexpected URL: {url}")

    http_tool = PinRunnerHttpTool()
    result = SecureCodingAgent(http_tool=http_tool).solve_challenge({
        "id": "pinsmith", "category": "secure_coding",
        "url": "http://127.0.0.1:30514",
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{pin_runner_1234}"
    assert http_tool.submission["language"] == "python"
    assert "current[-1] == digit" in http_tool.submission["code"]
    assert result["artifacts"]["coding_runner"] == "pin_enumeration"

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
            body = json.dumps({"content": self.saved[-1]["content"]}) if self.saved else self.source_body
            return SimpleNamespace(status_code=200, body_preview=body)
        if url.endswith("/api/save"):
            self.saved.append(json_data)
            return SimpleNamespace(status_code=200, body_preview='{"ok":true}')
        if url.endswith("/api/restart"):
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
    assert result["artifacts"]["techniques"] == [
        "partial_pin_constraint_enumeration",
        "remote_code_runner_submission",
    ]


def test_secure_coding_agent_discovers_and_patches_prototype_pollution():
    profile_source = """function deepMerge(target, source) {
  for (let key in source) {
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
"""
    exploit_source = """const payload = {\"__proto__\": {\"isAdmin\": true}};
// Alternative: constructor.prototype.isAdmin
"""

    class TreeHttpTool:
        def __init__(self):
            self.saved = None
            self.verify_count = 0
            self.restarted = False

        def fetch(self, url, *, method="GET", params=None, json_data=None, **kwargs):
            if url.rstrip("/").endswith("31337"):
                return SimpleNamespace(status_code=200, body_preview="not a coding runner")
            if url.endswith("/api/verify"):
                self.verify_count += 1
                body = '{"error":"not patched"}' if self.verify_count == 1 else '{"flag":"HTB{agri_fixed}"}'
                return SimpleNamespace(status_code=400 if self.verify_count == 1 else 200, body_preview=body)
            if url.endswith("/api/directory"):
                return SimpleNamespace(status_code=200, body_preview=json.dumps({
                    "routes": {"type": "folder", "children": {"profile.js": {"type": "file"}}},
                    "exploit": {"type": "folder", "children": {"solver.py": {"type": "file"}}},
                    "db": {"type": "folder", "children": {"app.db": {"type": "file"}}},
                }))
            if url.endswith("/api/file"):
                path = params["path"]
                if self.saved and path == self.saved["path"]:
                    content = self.saved["content"]
                else:
                    content = exploit_source if path == "exploit/solver.py" else profile_source
                return SimpleNamespace(status_code=200, body_preview=json.dumps({"content": content}))
            if url.endswith("/api/save"):
                self.saved = json_data
                return SimpleNamespace(status_code=200, body_preview='{"ok":true}')
            if url.endswith("/api/restart"):
                self.restarted = True
                return SimpleNamespace(status_code=200, body_preview='{"ok":true}')
            raise AssertionError(f"Unexpected URL: {url}")

    http_tool = TreeHttpTool()
    result = SecureCodingAgent(http_tool=http_tool).solve_challenge({
        "id": "agriweb", "category": "secure_coding", "url": "http://127.0.0.1:31337",
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{agri_fixed}"
    assert result["artifacts"]["vulnerability_class"] == "prototype_pollution"
    assert http_tool.saved["path"] == "routes/profile.js"
    assert "Object.prototype.hasOwnProperty.call(source, key)" in http_tool.saved["content"]
    assert "key === '__proto__'" in http_tool.saved["content"]
    assert http_tool.restarted is True

from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.specialists.cryptography.crypto_agent import CryptographyAgent


class DummyBrowserSnapshotTool:
    def run(self, url):
        return {"url": url, "title": "Dummy Page", "text_blocks": ["login form"]}


class DummyTonyAdapter:
    def solve(self, challenge, routing_steps=None):
        return {
            "challenge_id": challenge.get("id"),
            "agent_id": "tony_htb_sql",
            "status": "solved",
            "flag": None,
            "steps": (routing_steps or []) + ["Dummy Tony adapter ran"],
        }


def test_coordinator_runs_crypto_agent():
    coordinator = CoordinatorAgent()
    coordinator.register_agent(CryptographyAgent())

    challenge = {
        "id": "crypto_001",
        "name": "Crypto challenge",
        "category": "crypto",
        "description": "Decrypt this Caesar cipher: 'Khoor Zruog'",
        "hints": ["Try shifting the letters"],
        "tags": ["crypto", "caesar"],
        "metadata": {"cipher_type": "caesar"},
    }

    result = coordinator.solve_challenge(challenge)

    assert result["agent_id"] == "coordinator"
    assert result["status"] == "solved"
    assert result["flag"] == "Hello World"
    assert any(h["agent_id"] == "crypto_agent" for h in result["history"])


def test_coordinator_runs_browser_snapshot():
    coordinator = CoordinatorAgent(browser_snapshot_tool=DummyBrowserSnapshotTool())

    challenge = {
        "id": "web_001",
        "name": "Web challenge",
        "category": "web",
        "description": "Inspect the login form on the page",
        "target": {"url": "http://example.com"},
        "hints": [],
        "tags": ["web"],
        "metadata": {},
    }

    result = coordinator.solve_challenge(challenge)

    assert result["status"] == "attempted"
    # Find tool result in history
    tool_history = [h for h in result["history"] if h.get("routing", {}).get("selected_target") == "browser_snapshot"]
    assert len(tool_history) > 0
    assert "browser_snapshot" in tool_history[0]["artifacts"]


def test_coordinator_runs_tony_adapter():
    coordinator = CoordinatorAgent(tony_sql_adapter=DummyTonyAdapter())

    challenge = {
        "id": "web_002",
        "name": "SQLi challenge",
        "category": "web",
        "description": "Possible login bypass via SQL injection",
        "target": {"url": "http://example.com/login"},
        "hints": [],
        "tags": ["web", "sqli"],
        "metadata": {},
    }

    result = coordinator.solve_challenge(challenge)

    assert result["agent_id"] == "coordinator"
    assert result["status"] == "solved"
    assert any(h["agent_id"] == "tony_htb_sql" for h in result["history"])
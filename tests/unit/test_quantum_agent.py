from agents.specialists.quantum.quantum_agent import QuantumAgent


class FakeResponse:
    def __init__(self, data):
        self.data = data

    def raise_for_status(self):
        return None

    def json(self):
        return self.data


class OathSession:
    def __init__(self, rounds=2, strands=3):
        self.rounds = rounds
        self.strands = strands
        self.calls = []
        self.opened = 0

    def request(self, method, url, json=None, timeout=None):
        self.calls.append((method, url, json, timeout))
        path = "/" + url.split("/", 3)[-1] if "/" in url.split("://", 1)[-1] else "/"
        if path == "/api/oath":
            return FakeResponse({
                "commit": "POST /api/commit",
                "peek": "POST /api/peek",
                "open": "POST /api/open",
                "gates": "I X Y Z H S SDG and CX",
                "rounds": self.rounds,
                "strands": self.strands,
            })
        if path == "/api/new":
            return FakeResponse({"token": "token", "rounds": self.rounds, "strands": self.strands})
        if path == "/api/commit":
            assert json["slots"] == [[["H", "a"], ["CX", "a", "b"]]] * self.strands
            return FakeResponse({"challenge": self.opened % 2})
        if path == "/api/peek":
            assert json["basis"] == ("Z" if self.opened % 2 == 0 else "X")
            return FakeResponse({"a_outcomes": [self.opened % 2] * self.strands})
        if path == "/api/open":
            assert json["values"] == [self.opened % 2] * self.strands
            self.opened += 1
            result = {
                "round_held": True,
                "rounds_done": self.opened,
                "total": self.rounds,
            }
            if self.opened == self.rounds:
                result["flag"] = "HTB{epr_test_flag}"
            return FakeResponse(result)
        raise AssertionError(f"unexpected request path: {path}")


def test_quantum_agent_analysis_detects_commitment_protocol():
    analysis = QuantumAgent().analyze_challenge({
        "category": "misc",
        "name": "The Coin That Won't Land",
        "description": "Commit qubits, then measure your half in the court's chosen basis.",
    })

    assert analysis["can_handle"] is True
    assert analysis["confidence"] == 0.97
    assert "quantum_commitment_protocol" in analysis["detected_types"]


def test_quantum_agent_solves_oathbinding_with_epr_pairs(monkeypatch):
    monkeypatch.setenv("CTF_AGENTS_ALLOWED_NETWORKS", "quantum.test")
    session = OathSession()
    agent = QuantumAgent(session=session)

    result = agent.solve_challenge({
        "id": "oath",
        "category": "quantum",
        "url": "http://quantum.test:31112",
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{epr_test_flag}"
    assert result["techniques"] == ["bell_state_correlations", "epr_deferred_measurement"]
    assert session.opened == 2


def test_quantum_agent_rejects_unbounded_remote_work(monkeypatch):
    monkeypatch.setenv("CTF_AGENTS_ALLOWED_NETWORKS", "quantum.test")
    session = OathSession(rounds=QuantumAgent.MAX_ROUNDS + 1)

    result = QuantumAgent(session=session).solve_challenge({
        "id": "too_many_rounds",
        "category": "quantum",
        "url": "http://quantum.test:31112",
    })

    assert result["status"] == "attempted"
    assert "must be between" in result["steps"][-1]

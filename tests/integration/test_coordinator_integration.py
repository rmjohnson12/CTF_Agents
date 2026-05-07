"""
Integration tests for the coordinator loop.

These tests exercise coordinator + KnowledgeStore + MessageBroker +
PerformanceTracker together.  No LLM key is required; all tests run
against the heuristic fallback path or a controlled MockReasoner.

Distinction from unit tests (test_iterative_coordinator.py):
- Unit tests swap in MockReasoner + MockAgent to test loop logic.
- These tests assert cross-component data flow: agent results flowing into
  the knowledge store, broker messages being published, performance records
  being written, and prior knowledge being injected back into decisions.

Distinction from e2e tests (test_agents_e2e.py):
- e2e tests assert specific flag values for real challenge types.
- These tests assert coordinator-level wiring that no unit test catches.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from agents.base_agent import BaseAgent, AgentType
from agents.coordinator.coordinator_agent import CoordinatorAgent
from core.communication.message import MessageType
from core.communication.message_broker import MessageBroker
from core.decision_engine.llm_reasoner import ChallengeAnalysis
from core.decision_engine.performance_tracker import PerformanceTracker
from core.knowledge_base.knowledge_store import KnowledgeStore


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

class MockAgent(BaseAgent):
    """Minimal specialist stub: returns a controlled result."""

    def __init__(
        self,
        agent_id: str,
        status: str = "solved",
        flag: Optional[str] = None,
        artifacts: Optional[Dict[str, Any]] = None,
        raises: Optional[Exception] = None,
    ):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self._status = status
        self._flag = flag
        self._artifacts = artifacts or {}
        self._raises = raises
        self.solve_count = 0

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        return {"confidence": 0.9}

    def get_capabilities(self) -> List[str]:
        return []

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        self.solve_count += 1
        if self._raises:
            raise self._raises
        result: Dict[str, Any] = {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": self._status,
            "flag": self._flag,
            "steps": [f"{self.agent_id} ran"],
        }
        if self._artifacts:
            result["artifacts"] = self._artifacts
        return result


class MockReasoner:
    """Plays back a fixed list of decisions then stops."""

    def __init__(self, decisions: List[Dict[str, Any]]):
        self._decisions = decisions
        self._index = 0

    def analyze_challenge(self, challenge: Dict[str, Any]) -> ChallengeAnalysis:
        cat = challenge.get("category", "misc")
        return ChallengeAnalysis(
            category_guess=cat,
            confidence=0.9,
            reasoning="mock",
            recommended_target="none",
            recommended_action="stop",
            detected_indicators=[],
        )

    def choose_next_action(
        self,
        challenge: Dict[str, Any],
        analysis: ChallengeAnalysis,
        history: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        if self._index < len(self._decisions):
            d = self._decisions[self._index]
            self._index += 1
            return d
        return {"next_action": "stop", "target": "none", "reasoning": "exhausted"}


class CapturingReasoner:
    """Records every challenge dict passed to choose_next_action, then stops."""

    def __init__(self):
        self.captured: List[Dict[str, Any]] = []

    def analyze_challenge(self, challenge: Dict[str, Any]) -> ChallengeAnalysis:
        cat = challenge.get("category", "misc")
        return ChallengeAnalysis(cat, 0.9, "capturing", "none", "stop", [])

    def choose_next_action(
        self,
        challenge: Dict[str, Any],
        analysis: ChallengeAnalysis,
        history: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        self.captured.append(challenge.copy())
        return {"next_action": "stop", "target": "none", "reasoning": "captured"}


class StopReasoner:
    """Always stops immediately after analysis."""

    def analyze_challenge(self, challenge: Dict[str, Any]) -> ChallengeAnalysis:
        cat = challenge.get("category", "misc")
        return ChallengeAnalysis(cat, 0.9, "stop", "none", "stop", [])

    def choose_next_action(self, *_: Any) -> Dict[str, Any]:
        return {"next_action": "stop", "target": "none", "reasoning": "always stop"}


def _build_coordinator(
    tmp_path: Path,
    broker: Optional[MessageBroker] = None,
) -> tuple[CoordinatorAgent, KnowledgeStore, PerformanceTracker, MessageBroker]:
    """Return coordinator wired with tmp_path-scoped components."""
    ks = KnowledgeStore(db_path=str(tmp_path / "knowledge.db"))
    pt = PerformanceTracker(db_path=str(tmp_path / "performance.db"))
    broker = broker or MessageBroker()
    coord = CoordinatorAgent(knowledge_store=ks, broker=broker)
    coord.performance_tracker = pt
    return coord, ks, pt, broker


# ---------------------------------------------------------------------------
# Performance tracker
# ---------------------------------------------------------------------------

def test_performance_tracker_records_outcome_after_agent_run(tmp_path, monkeypatch):
    """After solve_challenge, the performance tracker has an entry for the agent."""
    monkeypatch.chdir(tmp_path)
    coord, ks, pt, _ = _build_coordinator(tmp_path)

    agent = MockAgent("solver_agent", status="solved", flag="CTF{perf}")
    coord.register_agent(agent)
    coord.reasoner = MockReasoner([
        {"next_action": "run_agent", "target": "solver_agent", "reasoning": "go"},
    ])

    coord.solve_challenge({"id": "perf_record_test", "category": "crypto", "description": "test"})

    rate = pt.get_success_rate("solver_agent", "crypto")
    assert rate == 1.0
    assert agent.solve_count == 1


def test_performance_hint_appears_in_steps_when_history_exists(tmp_path, monkeypatch):
    """
    When the performance tracker has enough history for a category, the
    coordinator includes a 'Performance hint:' line in the initial steps.
    """
    monkeypatch.chdir(tmp_path)
    coord, ks, pt, _ = _build_coordinator(tmp_path)

    for i in range(3):
        pt.record_outcome(
            agent_id="crypto_agent",
            category="crypto",
            challenge_id=f"prior_{i}",
            status="solved",
        )

    coord.reasoner = StopReasoner()
    result = coord.solve_challenge({
        "id": "hint_test",
        "category": "crypto",
        "description": "crypto challenge",
    })

    assert any("Performance hint:" in s for s in result["steps"])
    assert any("crypto_agent" in s for s in result["steps"])


# ---------------------------------------------------------------------------
# Knowledge store
# ---------------------------------------------------------------------------

def test_agent_artifacts_stored_in_knowledge_base(tmp_path, monkeypatch):
    """Artifacts returned by an agent are persisted to the KnowledgeStore."""
    monkeypatch.chdir(tmp_path)
    coord, ks, pt, _ = _build_coordinator(tmp_path)

    artifacts = {"open_ports": [22, 80], "hostname": "victim.local"}
    agent = MockAgent("recon_agent", status="attempted", artifacts=artifacts)
    coord.register_agent(agent)
    coord.reasoner = MockReasoner([
        {"next_action": "run_agent", "target": "recon_agent", "reasoning": "recon first"},
        {"next_action": "stop", "target": "none", "reasoning": "done"},
    ])

    coord.solve_challenge({"id": "artifact_test", "description": "test artifacts"})

    facts = ks.get_facts(challenge_id="artifact_test")
    keys_stored = {f["key"] for f in facts}
    assert "open_ports" in keys_stored
    assert "hostname" in keys_stored


def test_prior_knowledge_injected_into_subsequent_decisions(tmp_path, monkeypatch):
    """
    Facts stored in the KnowledgeStore for a challenge are injected into the
    challenge dict passed to choose_next_action on the next iteration.
    """
    monkeypatch.chdir(tmp_path)
    challenge_id = "knowledge_injection_test"
    coord, ks, pt, _ = _build_coordinator(tmp_path)

    ks.add_fact(
        challenge_id=challenge_id,
        agent_id="pre_seeder",
        key="target_ip",
        value="10.0.0.1",
    )

    capturing = CapturingReasoner()
    coord.reasoner = capturing

    coord.solve_challenge({"id": challenge_id, "description": "injection test"})

    assert len(capturing.captured) >= 1
    first_call = capturing.captured[0]
    assert "prior_knowledge" in first_call
    assert any(f["key"] == "target_ip" for f in first_call["prior_knowledge"])


def test_knowledge_scoped_to_challenge_id(tmp_path, monkeypatch):
    """Facts from challenge A must not appear in challenge B's knowledge query."""
    monkeypatch.chdir(tmp_path)
    coord, ks, pt, _ = _build_coordinator(tmp_path)

    ks.add_fact(
        challenge_id="challenge_A",
        agent_id="tester",
        key="secret",
        value="only A knows",
    )

    coord.reasoner = StopReasoner()
    coord.solve_challenge({"id": "challenge_B", "description": "challenge B"})

    b_facts = ks.get_facts(challenge_id="challenge_B")
    assert all(f["key"] != "secret" for f in b_facts)

    a_facts = ks.get_facts(challenge_id="challenge_A")
    assert any(f["key"] == "secret" for f in a_facts)


# ---------------------------------------------------------------------------
# Message broker
# ---------------------------------------------------------------------------

def test_broker_receives_result_report_after_agent_run(tmp_path, monkeypatch):
    """Every agent result triggers a RESULT_REPORT message on the broker."""
    monkeypatch.chdir(tmp_path)
    broker = MessageBroker()
    received: list = []
    broker.subscribe("*", received.append)

    coord, ks, pt, _ = _build_coordinator(tmp_path, broker=broker)
    agent = MockAgent("pub_agent", status="solved", flag="CTF{pub}")
    coord.register_agent(agent)
    coord.reasoner = MockReasoner([
        {"next_action": "run_agent", "target": "pub_agent", "reasoning": "run it"},
    ])

    coord.solve_challenge({"id": "broker_result_test", "description": "test"})

    result_reports = [m for m in received if m.message_type == MessageType.RESULT_REPORT]
    assert len(result_reports) >= 1
    assert result_reports[0].sender == "coordinator"


def test_broker_receives_knowledge_share_when_artifacts_present(tmp_path, monkeypatch):
    """When an agent result includes artifacts, a KNOWLEDGE_SHARE message is published."""
    monkeypatch.chdir(tmp_path)
    broker = MessageBroker()
    received: list = []
    broker.subscribe("*", received.append)

    coord, ks, pt, _ = _build_coordinator(tmp_path, broker=broker)
    agent = MockAgent(
        "artifact_agent",
        status="attempted",
        artifacts={"flag_hint": "check /admin"},
    )
    coord.register_agent(agent)
    coord.reasoner = MockReasoner([
        {"next_action": "run_agent", "target": "artifact_agent", "reasoning": "scan"},
        {"next_action": "stop", "target": "none", "reasoning": "done"},
    ])

    coord.solve_challenge({"id": "broker_ks_test", "description": "test"})

    knowledge_shares = [m for m in received if m.message_type == MessageType.KNOWLEDGE_SHARE]
    assert len(knowledge_shares) >= 1
    payload = knowledge_shares[0].payload
    assert "flag_hint" in payload.get("artifacts", {})


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_unregistered_agent_target_returns_failed_gracefully(tmp_path, monkeypatch):
    """
    When the reasoner targets an agent that is not registered, the coordinator
    must return a result with status 'failed' in the history, not raise.
    """
    monkeypatch.chdir(tmp_path)
    coord, ks, pt, _ = _build_coordinator(tmp_path)
    coord.reasoner = MockReasoner([
        {"next_action": "run_agent", "target": "ghost_agent", "reasoning": "try ghost"},
        {"next_action": "stop", "target": "none", "reasoning": "give up"},
    ])

    result = coord.solve_challenge({"id": "ghost_test", "description": "ghost"})

    assert result["status"] in ("attempted", "failed")
    assert any("not registered" in s for s in result["steps"])


def test_agent_exception_is_caught_and_loop_continues(tmp_path, monkeypatch):
    """
    If an agent raises an exception during solve_challenge, the coordinator
    must catch it, log it in steps, and continue the loop rather than crash.
    """
    monkeypatch.chdir(tmp_path)
    coord, ks, pt, _ = _build_coordinator(tmp_path)

    boom = MockAgent("boom_agent", raises=RuntimeError("catastrophic failure"))
    coord.register_agent(boom)
    coord.reasoner = MockReasoner([
        {"next_action": "run_agent", "target": "boom_agent", "reasoning": "try it"},
        {"next_action": "stop", "target": "none", "reasoning": "stop after boom"},
    ])

    result = coord.solve_challenge({"id": "exception_test", "description": "boom"})

    assert result["status"] in ("attempted", "failed")
    assert any("catastrophic failure" in s for s in result["steps"])


# ---------------------------------------------------------------------------
# Checkpoint / resume
# ---------------------------------------------------------------------------

def test_checkpoint_written_with_full_history_on_solve(tmp_path, monkeypatch):
    """
    After a successful solve, a checkpoint file contains the correct
    challenge_id and history entry from the solving agent.
    """
    monkeypatch.chdir(tmp_path)
    coord, ks, pt, _ = _build_coordinator(tmp_path)

    agent = MockAgent("checkpoint_agent", status="solved", flag="CTF{checkpointed}")
    coord.register_agent(agent)
    coord.reasoner = MockReasoner([
        {"next_action": "run_agent", "target": "checkpoint_agent", "reasoning": "solve it"},
    ])

    result = coord.solve_challenge({"id": "checkpoint_write_test", "description": "test"})

    checkpoint_path = tmp_path / "logs" / "checkpoints" / "checkpoint_write_test.json"
    assert checkpoint_path.exists(), "checkpoint file not written"

    data = json.loads(checkpoint_path.read_text())
    assert data["challenge_id"] == "checkpoint_write_test"
    solved_entries = [h for h in data["history"] if h.get("flag") == "CTF{checkpointed}"]
    assert len(solved_entries) >= 1
    assert result["status"] == "solved"


def test_resume_carries_forward_prior_history(tmp_path, monkeypatch):
    """
    When resume=True and a checkpoint exists, the coordinator starts with the
    prior history and the final history contains both the checkpoint entry and
    the new solve.
    """
    monkeypatch.chdir(tmp_path)
    checkpoint_dir = tmp_path / "logs" / "checkpoints"
    checkpoint_dir.mkdir(parents=True)

    prior_entry = {
        "challenge_id": "resume_int_test",
        "agent_id": "first_agent",
        "status": "attempted",
        "flag": None,
        "steps": ["first_agent ran"],
    }
    checkpoint_path = checkpoint_dir / "resume_int_test.json"
    checkpoint_path.write_text(json.dumps({
        "challenge_id": "resume_int_test",
        "timestamp": "2026-05-01T00:00:00",
        "iterations": 1,
        "history": [prior_entry],
        "steps": ["Iteration 1 decision: run_agent -> first_agent"],
    }))

    coord, ks, pt, _ = _build_coordinator(tmp_path)
    second_agent = MockAgent("second_agent", status="solved", flag="CTF{resumed}")
    coord.register_agent(second_agent)

    class SequentialReasoner:
        def analyze_challenge(self, c: Dict[str, Any]) -> ChallengeAnalysis:
            return ChallengeAnalysis("misc", 0.9, "seq", "none", "stop", [])

        def choose_next_action(
            self,
            challenge: Dict[str, Any],
            analysis: ChallengeAnalysis,
            history: List[Dict[str, Any]],
        ) -> Dict[str, Any]:
            if any(h.get("agent_id") == "first_agent" for h in history):
                return {
                    "next_action": "run_agent",
                    "target": "second_agent",
                    "reasoning": "first done, run second",
                }
            return {"next_action": "stop", "target": "none", "reasoning": "no history yet"}

    coord.reasoner = SequentialReasoner()

    result = coord.solve_challenge(
        {"id": "resume_int_test", "description": "resume test"},
        resume=True,
    )

    assert result["status"] == "solved"
    assert result["flag"] == "CTF{resumed}"
    agent_ids = [h["agent_id"] for h in result["history"]]
    assert "first_agent" in agent_ids
    assert "second_agent" in agent_ids
    assert any("Resuming from checkpoint" in s for s in result["steps"])

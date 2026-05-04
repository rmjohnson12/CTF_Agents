"""
Tests for MessageBroker wiring in CoordinatorAgent:
  - coordinator creates its own broker by default
  - coordinator accepts an external broker
  - RESULT_REPORT published after each agent/tool execution
  - KNOWLEDGE_SHARE published when artifacts are present
  - existing coordinator behaviour is not broken (regression)
"""

from datetime import datetime
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from agents.base_agent import AgentStatus, AgentType, BaseAgent
from agents.coordinator.coordinator_agent import CoordinatorAgent
from core.communication.message import MessageType
from core.communication.message_broker import MessageBroker


# ── helpers ───────────────────────────────────────────────────────────

class SolvedAgent(BaseAgent):
    """Specialist that immediately returns a solved result with a flag.

    Defaults to agent_id="crypto_agent" so the heuristic router
    (which maps cipher/crypto challenges -> "crypto_agent") finds it.
    """

    def __init__(self, agent_id: str = "crypto_agent", artifacts: Dict = None):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self._artifacts = artifacts or {}

    def analyze_challenge(self, challenge):
        return {"confidence": 1.0}

    def solve_challenge(self, challenge):
        result = {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": "solved",
            "flag": "CTF{test_flag}",
            "steps": ["found flag"],
        }
        if self._artifacts:
            result["artifacts"] = self._artifacts
        return result

    def get_capabilities(self):
        return ["testing"]


class FailingAgent(BaseAgent):
    """Specialist that always returns a failed result."""

    def __init__(self):
        super().__init__("crypto_agent", AgentType.SPECIALIST)

    def analyze_challenge(self, challenge):
        return {"confidence": 0.0}

    def solve_challenge(self, challenge):
        return {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": "failed",
            "flag": None,
            "steps": ["no luck"],
        }

    def get_capabilities(self):
        return ["testing"]


CRYPTO_CHALLENGE = {
    "id": "broker_test_001",
    "name": "Broker Test",
    "description": "Decrypt this Caesar cipher",
    "hints": [],
    "tags": ["crypto", "cipher"],
    "files": [],
    "metadata": {},
}


# ── broker creation ───────────────────────────────────────────────────

def test_coordinator_creates_default_broker():
    coordinator = CoordinatorAgent()
    assert coordinator.broker is not None
    assert isinstance(coordinator.broker, MessageBroker)


def test_coordinator_accepts_external_broker():
    external = MessageBroker()
    coordinator = CoordinatorAgent(broker=external)
    assert coordinator.broker is external


# ── RESULT_REPORT published after agent run ───────────────────────────

def test_result_report_published_after_agent_run():
    broker = MessageBroker()
    coordinator = CoordinatorAgent(broker=broker)

    agent = SolvedAgent()
    coordinator.register_agent(agent)

    coordinator.solve_challenge(CRYPTO_CHALLENGE)

    history = broker.get_history()
    result_reports = [m for m in history if m.message_type == MessageType.RESULT_REPORT]
    assert len(result_reports) >= 1, "Expected at least one RESULT_REPORT in broker history"


def test_result_report_payload_contains_result():
    broker = MessageBroker()
    coordinator = CoordinatorAgent(broker=broker)
    coordinator.register_agent(SolvedAgent())

    coordinator.solve_challenge(CRYPTO_CHALLENGE)

    reports = [m for m in broker.get_history() if m.message_type == MessageType.RESULT_REPORT]
    assert any("result" in m.payload for m in reports)
    assert any(m.payload["result"].get("flag") == "CTF{test_flag}" for m in reports)


def test_result_report_sender_is_coordinator():
    broker = MessageBroker()
    coordinator = CoordinatorAgent(broker=broker)
    coordinator.register_agent(SolvedAgent())

    coordinator.solve_challenge(CRYPTO_CHALLENGE)

    reports = [m for m in broker.get_history() if m.message_type == MessageType.RESULT_REPORT]
    assert all(m.sender == "coordinator" for m in reports)


# ── KNOWLEDGE_SHARE published when artifacts present ─────────────────

def test_knowledge_share_published_when_artifacts_present():
    broker = MessageBroker()
    coordinator = CoordinatorAgent(broker=broker)
    artifacts = {"decoded_text": "Hello World", "encoding": "base64"}
    coordinator.register_agent(SolvedAgent(artifacts=artifacts))

    coordinator.solve_challenge(CRYPTO_CHALLENGE)

    knowledge = [m for m in broker.get_history() if m.message_type == MessageType.KNOWLEDGE_SHARE]
    assert len(knowledge) >= 1, "Expected KNOWLEDGE_SHARE when agent returns artifacts"


def test_knowledge_share_payload_contains_artifacts():
    broker = MessageBroker()
    coordinator = CoordinatorAgent(broker=broker)
    artifacts = {"decoded_text": "Hello World"}
    coordinator.register_agent(SolvedAgent(artifacts=artifacts))

    coordinator.solve_challenge(CRYPTO_CHALLENGE)

    knowledge = [m for m in broker.get_history() if m.message_type == MessageType.KNOWLEDGE_SHARE]
    payloads = [m.payload for m in knowledge]
    assert any(p.get("artifacts") == artifacts for p in payloads)


def test_no_knowledge_share_when_no_artifacts():
    broker = MessageBroker()
    coordinator = CoordinatorAgent(broker=broker)
    coordinator.register_agent(SolvedAgent(artifacts={}))

    coordinator.solve_challenge(CRYPTO_CHALLENGE)

    knowledge = [m for m in broker.get_history() if m.message_type == MessageType.KNOWLEDGE_SHARE]
    assert len(knowledge) == 0, "Should not publish KNOWLEDGE_SHARE when artifacts dict is empty"


# ── broadcast subscribers receive messages ───────────────────────────

def test_subscriber_receives_result_report():
    broker = MessageBroker()
    received = []
    broker.subscribe("*", lambda m: received.append(m))

    coordinator = CoordinatorAgent(broker=broker)
    coordinator.register_agent(SolvedAgent())
    coordinator.solve_challenge(CRYPTO_CHALLENGE)

    result_reports = [m for m in received if m.message_type == MessageType.RESULT_REPORT]
    assert len(result_reports) >= 1


# ── regression: existing coordinator behaviour unchanged ──────────────

def test_coordinator_still_returns_solved_result():
    coordinator = CoordinatorAgent()
    coordinator.register_agent(SolvedAgent())

    result = coordinator.solve_challenge(CRYPTO_CHALLENGE)

    assert result["status"] == "solved"
    assert result["flag"] == "CTF{test_flag}"
    assert result["challenge_id"] == "broker_test_001"


def test_coordinator_still_populates_history():
    coordinator = CoordinatorAgent()
    coordinator.register_agent(SolvedAgent())

    result = coordinator.solve_challenge(CRYPTO_CHALLENGE)

    assert "history" in result
    assert len(result["history"]) >= 1


def test_coordinator_handles_failing_agent_gracefully():
    coordinator = CoordinatorAgent()

    failing = FailingAgent()
    coordinator.register_agent(failing)

    result = coordinator.solve_challenge(CRYPTO_CHALLENGE)
    assert result["challenge_id"] == "broker_test_001"
    assert result["status"] in ("attempted", "failed", "solved")

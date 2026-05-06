import pytest
import time
import json
from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.base_agent import BaseAgent, AgentType, AgentStatus
from typing import Dict, Any, List

class MockAgent(BaseAgent):
    def __init__(self, agent_id, status_on_solve="solved", flag=None):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.status_on_solve = status_on_solve
        self.flag = flag
        self.solve_called = 0

    def analyze_challenge(self, challenge):
        return {"confidence": 0.9}

    def solve_challenge(self, challenge):
        self.solve_called += 1
        return {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": self.status_on_solve,
            "flag": self.flag,
            "steps": [f"{self.agent_id} executed"]
        }

    def get_capabilities(self):
        return []

class SlowMockAgent(MockAgent):
    def solve_challenge(self, challenge):
        time.sleep(1)
        return super().solve_challenge(challenge)

class MockReasoner:
    def __init__(self, decisions):
        self.decisions = decisions
        self.index = 0
        self.analyze_called = 0

    def analyze_challenge(self, challenge):
        self.analyze_called += 1
        from core.decision_engine.llm_reasoner import ChallengeAnalysis
        return ChallengeAnalysis(
            category_guess="misc",
            confidence=0.9,
            reasoning="Initial analysis",
            recommended_target="none",
            recommended_action="stop",
            detected_indicators=[]
        )

    def choose_next_action(self, challenge, analysis, history):
        if self.index < len(self.decisions):
            d = self.decisions[self.index]
            self.index += 1
            return d
        return {"next_action": "stop", "target": "none", "reasoning": "No more decisions"}

class HistoryAwareReasoner(MockReasoner):
    def __init__(self):
        super().__init__([])

    def choose_next_action(self, challenge, analysis, history):
        if any(h.get("agent_id") == "agent_1" for h in history):
            return {"next_action": "run_agent", "target": "agent_2", "reasoning": "Resume with second agent"}
        return {"next_action": "run_agent", "target": "agent_1", "reasoning": "Start with first agent"}

def test_coordinator_iterative_loop_stops_on_solve():
    decisions = [
        {"next_action": "run_agent", "target": "agent_1", "reasoning": "Try first agent"},
        {"next_action": "run_agent", "target": "agent_2", "reasoning": "Try second agent"}
    ]
    reasoner = MockReasoner(decisions)
    coordinator = CoordinatorAgent()
    coordinator.reasoner = reasoner

    agent1 = MockAgent("agent_1", status_on_solve="attempted")
    agent2 = MockAgent("agent_2", status_on_solve="solved", flag="CTF{success}")
    
    coordinator.register_agent(agent1)
    coordinator.register_agent(agent2)

    challenge = {"id": "test_1", "description": "test loop"}
    result = coordinator.solve_challenge(challenge)

    assert result["status"] == "solved"
    assert result["flag"] == "CTF{success}"
    assert result["iterations"] == 2
    assert reasoner.analyze_called == 1
    assert agent1.solve_called == 1
    assert agent2.solve_called == 1

def test_coordinator_iterative_loop_stops_on_max_iterations():
    # Set up reasoner to keep going
    decisions = [
        {"next_action": "run_agent", "target": "agent_1", "reasoning": "Infinite loop simulation"}
    ] * 10
    reasoner = MockReasoner(decisions)
    coordinator = CoordinatorAgent(max_iterations=3)
    coordinator.reasoner = reasoner

    agent1 = MockAgent("agent_1", status_on_solve="attempted")
    coordinator.register_agent(agent1)

    challenge = {"id": "test_2", "description": "test max iterations"}
    result = coordinator.solve_challenge(challenge)

    assert result["iterations"] == 3
    assert result["status"] == "attempted"
    assert reasoner.analyze_called == 1
    assert agent1.solve_called == 3

def test_coordinator_does_not_resubmit_same_in_flight_target():
    decisions = [
        {"next_action": "run_agent", "target": "agent_1", "reasoning": "Try slow agent"}
    ] * 10
    reasoner = MockReasoner(decisions)
    coordinator = CoordinatorAgent(max_iterations=3)
    coordinator.reasoner = reasoner

    agent1 = SlowMockAgent("agent_1", status_on_solve="attempted")
    coordinator.register_agent(agent1)

    challenge = {"id": "test_in_flight", "description": "test duplicate in-flight target"}
    result = coordinator.solve_challenge(challenge)

    assert result["iterations"] == 3
    assert result["status"] == "attempted"
    assert agent1.solve_called == 1
    assert "Waiting for in-flight task: run_agent -> agent_1" in result["steps"]

def test_coordinator_iterative_loop_stops_on_reasoner_stop():
    decisions = [
        {"next_action": "run_agent", "target": "agent_1", "reasoning": "One try"},
        {"next_action": "stop", "target": "none", "reasoning": "Giving up"}
    ]
    reasoner = MockReasoner(decisions)
    coordinator = CoordinatorAgent()
    coordinator.reasoner = reasoner

    agent1 = MockAgent("agent_1", status_on_solve="attempted")
    coordinator.register_agent(agent1)

    challenge = {"id": "test_3", "description": "test stop"}
    result = coordinator.solve_challenge(challenge)

    assert result["iterations"] == 2
    assert result["status"] == "attempted"
    assert agent1.solve_called == 1


def test_coordinator_corrects_agent_target_marked_as_tool():
    decisions = [
        {"next_action": "run_tool", "target": "agent_1", "reasoning": "LLM confused an agent for a tool"}
    ]
    reasoner = MockReasoner(decisions)
    coordinator = CoordinatorAgent()
    coordinator.reasoner = reasoner

    agent1 = MockAgent("agent_1", status_on_solve="solved", flag="CTF{corrected}")
    coordinator.register_agent(agent1)

    result = coordinator.solve_challenge({"id": "test_correct_action", "description": "test correction"})

    assert result["status"] == "solved"
    assert result["flag"] == "CTF{corrected}"
    assert agent1.solve_called == 1
    assert "Corrected decision: run_tool -> agent_1 should be run_agent." in result["steps"]


def test_coordinator_keeps_live_jwt_web_target_on_web_agent():
    decisions = [
        {"next_action": "run_agent", "target": "crypto_agent", "reasoning": "JWT sounds cryptographic"}
    ]
    reasoner = MockReasoner(decisions)
    coordinator = CoordinatorAgent()
    coordinator.reasoner = reasoner

    crypto_agent = MockAgent("crypto_agent", status_on_solve="attempted")
    web_agent = MockAgent("web_agent", status_on_solve="solved", flag="HTB{web_jwt}")
    coordinator.register_agent(crypto_agent)
    coordinator.register_agent(web_agent)

    result = coordinator.solve_challenge({
        "id": "jwt_web",
        "category": "web",
        "description": "Help desk portal uses JWT tokens. Target is 154.57.164.65:30433",
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{web_jwt}"
    assert crypto_agent.solve_called == 0
    assert web_agent.solve_called == 1
    assert "Corrected decision: live JWT/session web target should use web_agent." in result["steps"]


def test_coordinator_writes_checkpoint_for_fast_solve(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    decisions = [
        {"next_action": "run_agent", "target": "agent_1", "reasoning": "Try fast agent"}
    ]
    reasoner = MockReasoner(decisions)
    coordinator = CoordinatorAgent()
    coordinator.reasoner = reasoner
    coordinator.register_agent(MockAgent("agent_1", status_on_solve="solved", flag="CTF{checkpointed}"))

    result = coordinator.solve_challenge({"id": "checkpoint_fast", "description": "test checkpoint"})

    checkpoint_path = tmp_path / "logs" / "checkpoints" / "checkpoint_fast.json"
    assert result["status"] == "solved"
    assert checkpoint_path.exists()

    checkpoint = json.loads(checkpoint_path.read_text())
    assert checkpoint["challenge_id"] == "checkpoint_fast"
    assert checkpoint["history"][0]["flag"] == "CTF{checkpointed}"
    assert any("Challenge solved" in step for step in checkpoint["steps"])


def test_coordinator_resumes_from_checkpoint_history(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    checkpoint_dir = tmp_path / "logs" / "checkpoints"
    checkpoint_dir.mkdir(parents=True)
    checkpoint_path = checkpoint_dir / "resume_me.json"
    checkpoint_path.write_text(json.dumps({
        "challenge_id": "resume_me",
        "timestamp": "2026-05-06T09:00:00",
        "iterations": 1,
        "history": [{
            "challenge_id": "resume_me",
            "agent_id": "agent_1",
            "status": "attempted",
            "flag": None,
            "steps": ["agent_1 executed"],
        }],
        "steps": [
            "Initial category guess: misc",
            "Initial confidence: 0.90",
            "Iteration 1 reasoning: Start with first agent",
            "Iteration 1 decision: run_agent -> agent_1",
            "  [Exec] agent_1 executed",
        ],
    }))

    coordinator = CoordinatorAgent(max_iterations=3)
    coordinator.reasoner = HistoryAwareReasoner()
    coordinator.register_agent(MockAgent("agent_1", status_on_solve="attempted"))
    coordinator.register_agent(MockAgent("agent_2", status_on_solve="solved", flag="CTF{resumed}"))

    result = coordinator.solve_challenge({"id": "resume_me", "description": "test resume"}, resume=True)

    assert result["status"] == "solved"
    assert result["flag"] == "CTF{resumed}"
    assert result["iterations"] == 2
    assert [h["agent_id"] for h in result["history"]] == ["agent_1", "agent_2"]
    assert any("Resuming from checkpoint" in step for step in result["steps"])

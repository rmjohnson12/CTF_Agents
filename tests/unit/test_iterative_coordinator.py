import pytest
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
            "status": self.status_on_solve,
            "flag": self.flag,
            "steps": [f"{self.agent_id} executed"]
        }

    def get_capabilities(self):
        return []

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
    assert agent1.solve_called == 3

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

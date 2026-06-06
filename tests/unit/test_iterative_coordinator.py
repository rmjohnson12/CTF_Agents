import pytest
import time
import json
import threading
from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.base_agent import BaseAgent, AgentType, AgentStatus
from core.knowledge_base.solve_trace_store import SolveTraceStore
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


class BrieflySlowMockAgent(MockAgent):
    def solve_challenge(self, challenge):
        time.sleep(0.05)
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

class RecoveryReasoner(MockReasoner):
    is_available = True

    def __init__(self):
        super().__init__([
            {"next_action": "run_agent", "target": "agent_1", "reasoning": "Try likely agent"},
            {"next_action": "stop", "target": "none", "reasoning": "Normal planner is stuck"},
        ])
        self.recovery_calls = 0

    def suggest_recovery_action(self, challenge, analysis, history, steps):
        self.recovery_calls += 1
        return {
            "next_action": "run_agent",
            "target": "agent_2",
            "reasoning": "Prior agent failed; pivot to the second specialist with a focused task.",
            "inputs": {"task": "Try a different decoding strategy based on the failed trace."},
        }


class DirectPwnRecoveryReasoner(MockReasoner):
    is_available = True

    def __init__(self):
        super().__init__([
            {"next_action": "stop", "target": "none", "reasoning": "Normal planner is stuck after pwn."},
        ])
        self.recovery_calls = 0

    def analyze_challenge(self, challenge):
        self.analyze_called += 1
        from core.decision_engine.llm_reasoner import ChallengeAnalysis
        return ChallengeAnalysis(
            category_guess="pwn",
            confidence=0.91,
            reasoning="Pwn challenge with source and remote.",
            recommended_target="pwn_agent",
            recommended_action="run_agent",
            detected_indicators=["pwn_terms"],
        )

    def suggest_recovery_action(self, challenge, analysis, history, steps):
        self.recovery_calls += 1
        return {
            "next_action": "run_agent",
            "target": "coding_agent",
            "reasoning": "Pwn specialist failed; inspect source and derive a payload script.",
            "inputs": {"task": "Analyze the pwn source and produce a remote payload."},
        }


class MaxIterationRecoveryReasoner(MockReasoner):
    is_available = True

    def __init__(self):
        super().__init__([
            {"next_action": "run_agent", "target": "agent_1", "reasoning": "Try first agent"},
            {"next_action": "run_agent", "target": "agent_2", "reasoning": "Try second agent"},
        ])
        self.recovery_calls = 0

    def suggest_recovery_action(self, challenge, analysis, history, steps):
        self.recovery_calls += 1
        return {
            "next_action": "run_agent",
            "target": "agent_3",
            "reasoning": "Iteration budget was exhausted; try the remaining specialist.",
            "inputs": {"task": "Last-chance recovery attempt."},
        }


class ExplodingPlannerReasoner(MockReasoner):
    def __init__(self):
        super().__init__([])

    def choose_next_action(self, challenge, analysis, history):
        raise AssertionError("direct category routing should bypass planner")


class WebSourceBrowserFirstReasoner(ExplodingPlannerReasoner):
    def analyze_challenge(self, challenge):
        from core.decision_engine.llm_reasoner import ChallengeAnalysis
        return ChallengeAnalysis(
            category_guess="web",
            confidence=0.89,
            reasoning="Web challenge requiring initial inspection. Recommending browser_snapshot.",
            recommended_target="browser_snapshot",
            recommended_action="run_tool",
            detected_indicators=["web_terms"],
        )


class CapturingMockAgent(MockAgent):
    def __init__(self, agent_id, status_on_solve="attempted", flag=None):
        super().__init__(agent_id, status_on_solve=status_on_solve, flag=flag)
        self.last_challenge = None

    def solve_challenge(self, challenge):
        self.last_challenge = challenge
        return super().solve_challenge(challenge)


class MainThreadAssertingAgent(MockAgent):
    def solve_challenge(self, challenge):
        assert threading.current_thread() is threading.main_thread()
        return super().solve_challenge(challenge)


class FailingPerformanceTracker:
    def get_routing_hint(self, category):
        raise RuntimeError("attempt to write a readonly database")

    def record_outcome(self, *args, **kwargs):
        raise RuntimeError("attempt to write a readonly database")

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


def test_coordinator_direct_initial_category_bypasses_planner():
    reasoner = ExplodingPlannerReasoner()
    coordinator = CoordinatorAgent()
    coordinator.reasoner = reasoner
    pwn_agent = MockAgent("pwn_agent", status_on_solve="solved", flag="HTB{direct_pwn}")
    coordinator.register_agent(pwn_agent)

    result = coordinator.solve_challenge({
        "id": "direct_pwn",
        "category": "pwn",
        "description": "Pwn challenge with files and host:port",
        "files": ["/tmp/execute"],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{direct_pwn}"
    assert pwn_agent.solve_called == 1
    assert any("maps directly to pwn_agent" in step for step in result["steps"])


def test_coordinator_runs_direct_pwn_on_main_thread():
    reasoner = ExplodingPlannerReasoner()
    coordinator = CoordinatorAgent()
    coordinator.reasoner = reasoner
    pwn_agent = MainThreadAssertingAgent("pwn_agent", status_on_solve="solved", flag="HTB{main_thread}")
    coordinator.register_agent(pwn_agent)

    result = coordinator.solve_challenge({
        "id": "direct_pwn_main_thread",
        "category": "pwn",
        "description": "Pwn challenge with files and host:port",
        "files": ["/tmp/restaurant"],
        "url": "http://127.0.0.1:31337",
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{main_thread}"
    assert pwn_agent.solve_called == 1


def test_coordinator_routes_from_solve_trace_memory_before_llm(tmp_path):
    store = SolveTraceStore(db_path=str(tmp_path / "solve_traces.db"))
    store.record_solve(
        {
            "id": "old_matrix_route",
            "category": "misc",
            "description": "matrix route state conjugation",
            "files": ["/tmp/output.json"],
        },
        {
            "challenge_id": "old_matrix_route",
            "agent_id": "coordinator",
            "status": "solved",
            "flag": "SVIBGR{old_matrix_flag}",
            "history": [
                {
                    "agent_id": "coding_agent",
                    "status": "solved",
                    "flag": "SVIBGR{old_matrix_flag}",
                    "routing": {
                        "selected_target": "coding_agent",
                        "execution_type": "agent",
                    },
                    "artifacts": {"solver_script": "solve.py"},
                }
            ],
        },
    )
    reasoner = ExplodingPlannerReasoner()
    coordinator = CoordinatorAgent(solve_trace_store=store)
    coordinator.reasoner = reasoner
    coding_agent = MockAgent("coding_agent", status_on_solve="solved", flag="SVIBGR{new_matrix_flag}")
    coordinator.register_agent(coding_agent)

    result = coordinator.solve_challenge({
        "id": "new_matrix_route",
        "category": "misc",
        "description": "Recover live route from encrypted matrices",
        "files": ["/tmp/new/output.json"],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "SVIBGR{new_matrix_flag}"
    assert coding_agent.solve_called == 1
    assert any("Trace memory:" in step for step in result["steps"])
    assert any("Trace memory matched a prior solved challenge" in step for step in result["steps"])


def test_coordinator_direct_pwn_attempt_skips_llm_recovery_by_default(monkeypatch, tmp_path):
    monkeypatch.delenv("CTF_AGENTS_ENABLE_PWN_LLM_RECOVERY", raising=False)
    reasoner = DirectPwnRecoveryReasoner()
    coordinator = CoordinatorAgent(
        solve_trace_store=SolveTraceStore(db_path=str(tmp_path / "solve_traces.db"))
    )
    coordinator.reasoner = reasoner
    pwn_agent = MockAgent("pwn_agent", status_on_solve="attempted")
    coding_agent = MockAgent("coding_agent", status_on_solve="solved", flag="HTB{pwn_recovered}")
    coordinator.register_agent(pwn_agent)
    coordinator.register_agent(coding_agent)

    result = coordinator.solve_challenge({
        "id": "direct_pwn_attempted",
        "category": "pwn",
        "description": "Pwn challenge with unavailable remote",
        "files": ["/tmp/execute"],
    })

    assert result["status"] == "attempted"
    assert result["flag"] is None
    assert pwn_agent.solve_called == 1
    assert coding_agent.solve_called == 0
    assert reasoner.recovery_calls == 0
    assert any("Skipping pwn LLM recovery by default" in step for step in result["steps"])


def test_coordinator_direct_pwn_attempt_can_recover_with_llm_when_enabled(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_AGENTS_ENABLE_PWN_LLM_RECOVERY", "1")
    reasoner = DirectPwnRecoveryReasoner()
    coordinator = CoordinatorAgent(
        solve_trace_store=SolveTraceStore(db_path=str(tmp_path / "solve_traces.db"))
    )
    coordinator.reasoner = reasoner
    pwn_agent = MockAgent("pwn_agent", status_on_solve="attempted")
    coding_agent = MockAgent("coding_agent", status_on_solve="solved", flag="HTB{pwn_recovered}")
    coordinator.register_agent(pwn_agent)
    coordinator.register_agent(coding_agent)

    result = coordinator.solve_challenge({
        "id": "direct_pwn_attempted_opt_in",
        "category": "pwn",
        "description": "Pwn challenge with unavailable remote",
        "files": ["/tmp/execute"],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{pwn_recovered}"
    assert pwn_agent.solve_called == 1
    assert coding_agent.solve_called == 1
    assert reasoner.recovery_calls == 1
    assert not any("stopping before LLM planning" in step for step in result["steps"])
    assert any("LLM failure review suggested recovery" in step for step in result["steps"])


def test_coordinator_routes_source_backed_web_to_web_agent_before_snapshot():
    reasoner = WebSourceBrowserFirstReasoner()
    coordinator = CoordinatorAgent()
    coordinator.reasoner = reasoner
    web_agent = MockAgent("web_agent", status_on_solve="solved", flag="SVIBGR{source_web}")
    coordinator.register_agent(web_agent)

    result = coordinator.solve_challenge({
        "id": "source_backed_web",
        "category": "web",
        "description": "Public status page with local source files.",
        "url": "https://status.test",
        "files": ["/tmp/source/app.py"],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "SVIBGR{source_web}"
    assert web_agent.solve_called == 1
    assert any("maps directly to web_agent" in step for step in result["steps"])


def test_coordinator_waits_for_direct_first_agent_before_replanning():
    reasoner = ExplodingPlannerReasoner()
    coordinator = CoordinatorAgent()
    coordinator.reasoner = reasoner
    web_agent = BrieflySlowMockAgent("web_agent", status_on_solve="solved", flag="SVIBGR{fast_source}")
    coordinator.register_agent(web_agent)

    result = coordinator.solve_challenge({
        "id": "direct_wait_source_web",
        "category": "web",
        "description": "Public status page with local source files.",
        "url": "https://status.test",
        "files": ["/tmp/source/app.py"],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "SVIBGR{fast_source}"
    assert web_agent.solve_called == 1
    assert result["iterations"] == 1


def test_coordinator_iterative_loop_stops_on_max_iterations():
    # Set up reasoner to keep going with different targets to avoid duplicate check
    decisions = [
        {"next_action": "run_agent", "target": f"agent_{i+1}", "reasoning": "Infinite loop simulation"}
        for i in range(10)
    ]
    reasoner = MockReasoner(decisions)
    coordinator = CoordinatorAgent(max_iterations=3)
    coordinator.reasoner = reasoner
    
    for i in range(3):
        coordinator.register_agent(MockAgent(f"agent_{i+1}", status_on_solve="attempted"))

    challenge = {"id": "test_2", "description": "test max iterations"}
    result = coordinator.solve_challenge(challenge)

    assert result["iterations"] == 3
    assert result["status"] == "attempted"
    assert reasoner.analyze_called == 1
    # Total calls across all agents should be 3
    total_calls = sum(a.solve_called for a in coordinator.specialist_agents.values())
    assert total_calls == 3

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


def test_coordinator_asks_llm_for_recovery_after_failed_stop():
    reasoner = RecoveryReasoner()
    coordinator = CoordinatorAgent(max_iterations=4)
    coordinator.reasoner = reasoner

    agent1 = MockAgent("agent_1", status_on_solve="attempted")
    agent2 = MockAgent("agent_2", status_on_solve="solved", flag="CTF{recovered}")
    coordinator.register_agent(agent1)
    coordinator.register_agent(agent2)

    result = coordinator.solve_challenge({"id": "test_recovery", "description": "test recovery"})

    assert result["status"] == "solved"
    assert result["flag"] == "CTF{recovered}"
    assert agent1.solve_called == 1
    assert agent2.solve_called == 1
    assert reasoner.recovery_calls == 1
    assert any("LLM failure review suggested recovery" in step for step in result["steps"])


def test_coordinator_solves_when_performance_telemetry_fails(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    decisions = [
        {"next_action": "run_agent", "target": "agent_1", "reasoning": "Try the agent"}
    ]
    reasoner = MockReasoner(decisions)
    coordinator = CoordinatorAgent(performance_tracker=FailingPerformanceTracker())
    coordinator.reasoner = reasoner
    coordinator.register_agent(MockAgent("agent_1", status_on_solve="solved", flag="CTF{no_telemetry}"))

    result = coordinator.solve_challenge({"id": "readonly_perf_db", "description": "test telemetry failure"})

    assert result["status"] == "solved"
    assert result["flag"] == "CTF{no_telemetry}"
    assert not any("Task readonly_perf_db_step_1 failed" in step for step in result["steps"])


def test_coordinator_records_solved_trace_for_learning_database(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = SolveTraceStore(db_path=str(tmp_path / "logs" / "solve_traces.db"))
    decisions = [
        {"next_action": "run_agent", "target": "agent_1", "reasoning": "Try the agent"}
    ]
    reasoner = MockReasoner(decisions)
    coordinator = CoordinatorAgent(solve_trace_store=store)
    coordinator.reasoner = reasoner
    coordinator.register_agent(MockAgent("agent_1", status_on_solve="solved", flag="CTF{trace_saved}"))

    result = coordinator.solve_challenge({
        "id": "trace_db",
        "category": "misc",
        "description": "test solve trace database",
    })
    rows = store.get_recent_solves(category="misc")

    assert result["status"] == "solved"
    assert len(rows) == 1
    assert rows[0]["challenge_id"] == "trace_db"
    assert rows[0]["flag_prefix"] == "CTF"
    assert rows[0]["successful_agent"] == "agent_1"
    assert rows[0]["route_signature"] == "agent:agent_1:solved"


def test_coordinator_asks_llm_for_final_recovery_after_iteration_limit():
    reasoner = MaxIterationRecoveryReasoner()
    coordinator = CoordinatorAgent(max_iterations=2)
    coordinator.reasoner = reasoner

    coordinator.register_agent(MockAgent("agent_1", status_on_solve="attempted"))
    coordinator.register_agent(MockAgent("agent_2", status_on_solve="attempted"))
    agent3 = MockAgent("agent_3", status_on_solve="solved", flag="CTF{last_chance}")
    coordinator.register_agent(agent3)

    result = coordinator.solve_challenge({"id": "test_final_recovery", "description": "test final recovery"})

    assert result["status"] == "solved"
    assert result["flag"] == "CTF{last_chance}"
    assert agent3.solve_called == 1
    assert reasoner.recovery_calls == 1
    assert any("LLM failure review suggested final recovery" in step for step in result["steps"])


def test_coordinator_final_recovery_hydrates_prior_knowledge():
    reasoner = MaxIterationRecoveryReasoner()
    coordinator = CoordinatorAgent(max_iterations=2)
    coordinator.reasoner = reasoner

    coordinator.register_agent(MockAgent("agent_1", status_on_solve="attempted"))
    coordinator.register_agent(MockAgent("agent_2", status_on_solve="attempted"))
    agent3 = CapturingMockAgent("agent_3", status_on_solve="solved", flag="CTF{knowledge}")
    coordinator.register_agent(agent3)
    coordinator.knowledge_store.add_fact(
        challenge_id="knowledge_recovery",
        agent_id="docker_agent",
        key="docker_target_url",
        value="http://127.0.0.1:8080",
    )

    result = coordinator.solve_challenge({"id": "knowledge_recovery", "description": "test final recovery"})

    assert result["status"] == "solved"
    assert agent3.last_challenge["url"] == "http://127.0.0.1:8080"
    assert agent3.last_challenge["prior_knowledge"][0]["value"] == "http://127.0.0.1:8080"


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
    assert any("maps directly to web_agent" in step for step in result["steps"])


def test_coordinator_corrects_rsa_time_capsule_service_to_crypto_agent(tmp_path):
    challenge_dir = tmp_path / "baby_time_capsule"
    challenge_dir.mkdir()
    server = challenge_dir / "server.py"
    server.write_text(
        "class TimeCapsule:\n"
        "    def __init__(self):\n"
        "        self.e = 5\n"
        "    def get_new_time_capsule(self):\n"
        "        return {'time_capsule': 'AA', 'pubkey': ['BB', '5']}\n"
    )
    decisions = [
        {"next_action": "run_agent", "target": "web_agent", "reasoning": "IP target looks web-ish"}
    ]
    reasoner = MockReasoner(decisions)
    coordinator = CoordinatorAgent()
    coordinator.reasoner = reasoner

    crypto_agent = MockAgent("crypto_agent", status_on_solve="solved", flag="HTB{rsa_fixed}")
    web_agent = MockAgent("web_agent", status_on_solve="attempted")
    coordinator.register_agent(crypto_agent)
    coordinator.register_agent(web_agent)

    result = coordinator.solve_challenge({
        "id": "baby_time_capsule",
        "category": "crypto",
        "description": "Very easy crypto challenge. Ip and Port are 154.57.164.65:31813",
        "files": [str(server)],
        "url": "http://154.57.164.65:31813",
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{rsa_fixed}"
    assert crypto_agent.solve_called == 1
    assert web_agent.solve_called == 0
    assert any("maps directly to crypto_agent" in step for step in result["steps"])


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


def test_coordinator_sanitizes_checkpoint_id_path_traversal(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    reasoner = MockReasoner([
        {"next_action": "run_agent", "target": "agent_1", "reasoning": "Try fast agent"}
    ])
    coordinator = CoordinatorAgent()
    coordinator.reasoner = reasoner
    coordinator.register_agent(MockAgent("agent_1", status_on_solve="solved", flag="CTF{safe_checkpoint}"))

    result = coordinator.solve_challenge({"id": "../../outside", "description": "test checkpoint"})

    assert result["status"] == "solved"
    assert result["challenge_id"] == "outside"
    assert (tmp_path / "logs" / "checkpoints" / "outside.json").exists()
    assert not (tmp_path / "outside.json").exists()


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

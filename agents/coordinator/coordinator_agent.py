"""
Coordinator Agent

Main orchestrator for the CTF solving workflow.
Uses an LLM-backed decision layer (with heuristic fallback) to decide
which specialist agent or tool to run next.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from agents.base_agent import BaseAgent, AgentType, AgentStatus
from core.communication.message import Message, MessageType, MessagePriority
from core.communication.message_broker import MessageBroker
from core.decision_engine.llm_reasoner import LLMReasoner, ChallengeAnalysis
from core.decision_engine.performance_tracker import PerformanceTracker
from core.utils.result_manager import ResultManager
from core.task_manager.task_queue import TaskQueue
from core.task_manager.task import Task, TaskPriority
from core.knowledge_base.knowledge_store import KnowledgeStore
from core.knowledge_base.solve_trace_store import SolveTraceStore
from core.utils.security import redact_sensitive_data, safe_checkpoint_path, safe_slug
import concurrent.futures

logger = logging.getLogger(__name__)


class CoordinatorAgent(BaseAgent):
    """
    Coordinator agent that manages the multi-agent system.

    Responsibilities:
    - Analyze incoming challenges
    - Route challenges to specialist agents or tools
    - Monitor execution status
    - Aggregate results
    - Record routing rationale
    """

    def __init__(
        self,
        agent_id: str = "coordinator",
        browser_snapshot_tool: Optional[Any] = None,
        tony_sql_adapter: Optional[Any] = None,
        llm_client: Optional[Any] = None,
        max_iterations: int = 5,
        broker: Optional[MessageBroker] = None,
        knowledge_store: Optional[KnowledgeStore] = None,
        solve_trace_store: Optional[SolveTraceStore] = None,
        performance_tracker: Optional[Any] = None,
    ):
        ks = knowledge_store or KnowledgeStore()
        super().__init__(agent_id, AgentType.COORDINATOR, knowledge_store=ks)

        self.specialist_agents: Dict[str, BaseAgent] = {}
        self.support_agents: Dict[str, BaseAgent] = {}
        self.active_challenges: Dict[str, Dict[str, Any]] = {}
        self.performance_tracker = performance_tracker or self._create_performance_tracker()

        self.browser_snapshot_tool = browser_snapshot_tool
        self.tony_sql_adapter = tony_sql_adapter
        self.reasoner = LLMReasoner(client=llm_client)
        self.max_iterations = max_iterations
        self.result_manager = ResultManager()
        self.solve_trace_store = solve_trace_store or self._create_solve_trace_store()
        self.broker = broker or MessageBroker()
        self.task_queue = TaskQueue()

    def register_agent(self, agent: BaseAgent):
        """Register a specialist or support agent with the coordinator."""
        # Share knowledge store with the specialist
        agent.knowledge_store = self.knowledge_store
        
        if agent.agent_type == AgentType.SPECIALIST:
            self.specialist_agents[agent.agent_id] = agent
        elif agent.agent_type == AgentType.SUPPORT:
            self.support_agents[agent.agent_id] = agent

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a challenge and determine the best routing strategy.

        Returns:
            Structured analysis containing routing decision and metadata.
        """
        analysis = self.reasoner.analyze_challenge(challenge)
        return self._analysis_to_dict(challenge, analysis)

    def _analysis_to_dict(
        self,
        challenge: Dict[str, Any],
        analysis: ChallengeAnalysis,
    ) -> Dict[str, Any]:
        return {
            "challenge_id": challenge.get("id"),
            "category": analysis.category_guess,
            "difficulty": challenge.get("difficulty", "medium"),
            "assigned_agents": [analysis.recommended_target] if analysis.recommended_target != "none" else [],
            "strategy": {
                "action": analysis.recommended_action,
                "target": analysis.recommended_target,
                "reasoning": analysis.reasoning,
                "detected_indicators": analysis.detected_indicators,
            },
            "confidence": analysis.confidence,
        }

    def solve_challenge(self, challenge: Dict[str, Any], resume: bool = False) -> Dict[str, Any]:
        """
        Coordinate the solving of a challenge in an iterative loop using TaskQueue.
        Supports parallel execution of independent tasks.
        Persists checkpoint after each iteration to logs/checkpoints/.
        """
        challenge_id = safe_slug(challenge.get("id", "unknown_challenge"))
        challenge["id"] = challenge_id
        self.active_challenges[challenge_id] = challenge
        checkpoint_dir = Path("logs/checkpoints")

        initial_analysis_obj = self.reasoner.analyze_challenge(challenge)
        initial_analysis = self._analysis_to_dict(challenge, initial_analysis_obj)
        checkpoint = self._load_checkpoint(checkpoint_dir, challenge_id) if resume else None
        history: List[Dict[str, Any]] = checkpoint.get("history", []) if checkpoint else []
        trace_hints = self._get_solve_trace_hints_best_effort(challenge)
        
        if checkpoint:
            all_steps = checkpoint.get("steps", [])
            all_steps.append(f"Resuming from checkpoint with {len(history)} prior result(s).")
            start_iteration = int(checkpoint.get("iterations", len(history)))
        else:
            all_steps = [
                f"Initial category guess: {initial_analysis['category']}",
                f"Initial confidence: {initial_analysis['confidence']:.2f}",
            ]
            hint = self._get_routing_hint_best_effort(initial_analysis["category"])
            if hint:
                all_steps.append(
                    f"Performance hint: '{hint[0]}' has a {hint[1]:.0%} historical solve rate "
                    f"for '{initial_analysis['category']}' challenges."
                )
            start_iteration = 0

        if trace_hints:
            top_hint = trace_hints[0]
            all_steps.append(
                "Trace memory: "
                f"{len(trace_hints)} similar solved pattern(s); top target "
                f"{top_hint.get('successful_target')} "
                f"(score {top_hint.get('similarity_score')}, "
                f"shared {top_hint.get('shared_indicators')})."
            )

        final_result = {
            "challenge_id": challenge_id,
            "agent_id": self.agent_id,
            "status": "attempted",
            "flag": None,
            "steps": all_steps,
            "iterations": 0,
        }

        # Thread pool for parallel execution
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)
        futures = {}
        deferred_duplicate_targets = set()
        recovery_review_attempted = False

        def record_task_result(
            task_info: Dict[str, Any],
            result: Dict[str, Any],
            step_prefix: str,
        ) -> Optional[Dict[str, Any]]:
            task_id = task_info["task_id"]
            self.task_queue.complete_task(task_id, result)
            history.append(result)
            if result.get("steps"):
                all_steps.extend([f"  [{step_prefix}] {s}" for s in result["steps"]])

            self._publish_result(result)
            if result.get("artifacts"):
                self._publish_knowledge(challenge_id, result["artifacts"])

            if result.get("status") == "solved" or result.get("flag"):
                final_result["status"] = "solved"
                final_result["flag"] = result.get("flag")
                all_steps.append(f"Challenge solved by task {task_id}!")
                self._cleanup_run_artifacts(history, all_steps)
                return final_result

            return None

        def record_completed_future(f, step_prefix: str) -> Optional[Dict[str, Any]]:
            task_info = futures.pop(f)
            task_id = task_info["task_id"]
            try:
                result = f.result()
                return record_task_result(task_info, result, step_prefix)
            except Exception as e:
                all_steps.append(f"Task {task_id} failed: {e}")
                self.task_queue.fail_task(task_id, str(e))

            return None

        try:
            for i in range(start_iteration, self.max_iterations):
                final_result["iterations"] = i + 1
                
                # Check for completed futures
                done, not_done = concurrent.futures.wait(
                    futures.keys(), timeout=0.1, return_when=concurrent.futures.FIRST_COMPLETED
                )
                for f in done:
                    completed_result = record_completed_future(f, "Async Result")
                    if completed_result is not None:
                        completed_result["steps"] = all_steps
                        completed_result["history"] = history
                        self.active_challenges.pop(challenge_id, None)
                        self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)
                        self._record_solve_trace_best_effort(challenge, completed_result)
                        self._save_run_result_best_effort(completed_result)
                        return completed_result

                # Fetch prior knowledge for this challenge to inform the next decision
                prior_facts = self.knowledge_store.get_facts(challenge_id=challenge_id)
                challenge_with_knowledge = challenge.copy()
                if prior_facts:
                    challenge_with_knowledge["prior_knowledge"] = prior_facts
                    all_steps.append(f"  [Knowledge] Retrieved {len(prior_facts)} fact(s) from storage.")
                if trace_hints:
                    challenge_with_knowledge["solve_trace_hints"] = trace_hints

                direct_target = self._direct_initial_agent(challenge_with_knowledge, initial_analysis_obj)
                if not history and not futures and direct_target:
                    decision = {
                        "next_action": "run_agent",
                        "target": direct_target,
                        "reasoning": (
                            f"Parsed category '{challenge.get('category')}' maps directly to "
                            f"{direct_target}; dispatching before LLM planning."
                        ),
                        "inputs": {},
                    }
                else:
                    trace_decision = self._decision_from_trace_hints(trace_hints, history)
                    if trace_decision:
                        decision = trace_decision
                    else:
                        decision = self.reasoner.choose_next_action(
                            challenge_with_knowledge,
                            initial_analysis_obj,
                            history
                        )

                action = decision.get("next_action", "stop")
                target = decision.get("target", "none")
                reasoning = decision.get("reasoning", "No reasoning provided.")
                recovery_decision = False
                action, target = self._normalize_decision(action, target, challenge, all_steps)
                decision_key = (action, target)

                # Correct common reasoner mixups (agents vs tools)
                if action == "run_tool" and target in self._all_agent_ids():
                    action = "run_agent"
                elif action == "run_agent" and target in ["browser_snapshot", "tony_htb_sql"]:
                    action = "run_tool"

                if action == "stop":
                    if not futures:
                        recovery = self._request_recovery_action_once(
                            challenge_with_knowledge,
                            initial_analysis_obj,
                            history,
                            all_steps,
                            recovery_review_attempted,
                        )
                        recovery_review_attempted = True
                        if recovery:
                            decision = recovery
                            action = decision.get("next_action", "stop")
                            target = decision.get("target", "none")
                            reasoning = decision.get("reasoning", "No recovery reasoning provided.")
                            action, target = self._normalize_decision(action, target, challenge, all_steps)
                            decision_key = (action, target)
                            recovery_decision = True
                            all_steps.append(
                                f"LLM failure review suggested recovery: {action} -> {target}. {reasoning}"
                            )
                        else:
                            all_steps.append("Reasoner requested to stop.")
                            self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)
                            break
                    else:
                        all_steps.append("Reasoner requested to stop, but tasks are still running...")
                        self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)
                        continue

                if action == "stop":
                    if not futures:
                        all_steps.append("Reasoner requested to stop.")
                        self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)
                        break
                    else:
                        all_steps.append("Reasoner requested to stop, but tasks are still running...")
                        self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)
                        continue

                # Decision Quality: Check if we've already done this exact thing in this run
                # without getting any new hints or knowledge.
                has_new_info = (
                    recovery_decision
                    or "User Hint:" in challenge.get("description", "")
                    or (prior_facts and len(prior_facts) > 0)
                )
                
                is_duplicate = any(
                    h.get("routing", {}).get("selected_target") == target and
                    h.get("routing", {}).get("execution_type") == ("agent" if action == "run_agent" else "tool") and
                    h.get("challenge_id") == challenge_id
                    for h in history
                )
                
                if is_duplicate and not has_new_info:
                    all_steps.append(f"Skipping duplicate task: {action} -> {target} (already attempted and no new info)")
                    continue

                if any(info["action"] == action and info["target"] == target for info in futures.values()):
                    all_steps.append(f"Waiting for in-flight task: {action} -> {target}")
                    self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)
                    done, _ = concurrent.futures.wait(
                        futures.keys(), timeout=10, return_when=concurrent.futures.FIRST_COMPLETED
                    )
                    for f in done:
                        completed_result = record_completed_future(f, "Async Result")
                        if completed_result is not None:
                            completed_result["steps"] = all_steps
                            completed_result["history"] = history
                            self.active_challenges.pop(challenge_id, None)
                            self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)
                            self._record_solve_trace_best_effort(challenge, completed_result)
                            self._save_run_result_best_effort(completed_result)
                            return completed_result
                    if done:
                        deferred_duplicate_targets.add(decision_key)
                    continue

                if decision_key in deferred_duplicate_targets:
                    all_steps.append(f"Target already completed without a solution: {action} -> {target}. Stopping to avoid a retry loop.")
                    self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)
                    break

                task_id = f"{challenge_id}_step_{i+1}"
                task = Task(
                    id=task_id,
                    description=reasoning,
                    priority=TaskPriority.HIGH,
                    category=initial_analysis['category'],
                    metadata={"action": action, "target": target}
                )
                self.task_queue.add_task(task)
                
                current_task = self.task_queue.get_next_task()
                if not current_task:
                    continue

                all_steps.append(f"Iteration {i+1} reasoning: {reasoning}")
                all_steps.append(f"Iteration {i+1} decision: {action} -> {target}")

                # Execute action (using thread pool for agents/tools)
                if action == "run_agent":
                    # Re-fetch knowledge specifically for the specialist agent
                    prior_facts = self.knowledge_store.get_facts(challenge_id=challenge_id)
                    agent_challenge = challenge.copy()
                    if prior_facts:
                        agent_challenge["prior_knowledge"] = prior_facts
                        self._hydrate_challenge_from_facts(agent_challenge, prior_facts)
                        
                    if decision.get("inputs", {}).get("task"):
                        agent_challenge['current_task_description'] = decision["inputs"]["task"]
                    
                    direct_target = self._direct_initial_agent(challenge, initial_analysis_obj)
                    run_direct_pwn_in_main_thread = (
                        not history
                        and not futures
                        and target == direct_target == "pwn_agent"
                    )
                    task_info = {"task_id": task_id, "action": action, "target": target}
                    if run_direct_pwn_in_main_thread:
                        try:
                            result = self._run_selected_agent(agent_challenge, target, [])
                            completed_result = record_task_result(task_info, result, "Exec")
                            if completed_result is not None:
                                completed_result["steps"] = all_steps
                                completed_result["history"] = history
                                self.active_challenges.pop(challenge_id, None)
                                self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)
                                self._record_solve_trace_best_effort(challenge, completed_result)
                                self._save_run_result_best_effort(completed_result)
                                return completed_result
                        except Exception as e:
                            all_steps.append(f"Task {task_id} failed: {e}")
                            self.task_queue.fail_task(task_id, str(e))
                        self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)
                        continue

                    f = executor.submit(self._run_selected_agent, agent_challenge, target, [])
                    futures[f] = task_info
                elif action == "run_tool":
                    f = executor.submit(self._run_selected_tool, challenge, target, [])
                    futures[f] = {"task_id": task_id, "action": action, "target": target}
                else:
                    all_steps.append(f"Unknown action: {action}")
                    self.task_queue.fail_task(task_id, f"Unknown action: {action}")
                    self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)
                    continue

                direct_target = self._direct_initial_agent(challenge, initial_analysis_obj)
                initial_direct_wait_s = 8.0 if (
                    not history
                    and action == "run_agent"
                    and target == direct_target
                ) else 0.01
                just_done, _ = concurrent.futures.wait([f], timeout=initial_direct_wait_s)
                if f in just_done:
                    completed_result = record_completed_future(f, "Exec")
                    if completed_result is not None:
                        completed_result["steps"] = all_steps
                        completed_result["history"] = history
                        self.active_challenges.pop(challenge_id, None)
                        self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)
                        self._record_solve_trace_best_effort(challenge, completed_result)
                        self._save_run_result_best_effort(completed_result)
                        return completed_result

                self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)

            # Wait for any remaining tasks
            if futures:
                all_steps.append(f"Waiting for {len(futures)} remaining tasks...")
                done, _ = concurrent.futures.wait(futures.keys(), timeout=30)
                for f in done:
                    record_completed_future(f, "Exec")

            if final_result.get("status") != "solved":
                recovery = self._request_recovery_action_once(
                    challenge,
                    initial_analysis_obj,
                    history,
                    all_steps,
                    recovery_review_attempted,
                )
                recovery_review_attempted = True
                if recovery:
                    action = recovery.get("next_action", "stop")
                    target = recovery.get("target", "none")
                    reasoning = recovery.get("reasoning", "No recovery reasoning provided.")
                    action, target = self._normalize_decision(action, target, challenge, all_steps)
                    all_steps.append(
                        f"LLM failure review suggested final recovery: {action} -> {target}. {reasoning}"
                    )
                    if action == "run_agent":
                        prior_facts = self.knowledge_store.get_facts(challenge_id=challenge_id)
                        recovery_challenge = challenge.copy()
                        if prior_facts:
                            recovery_challenge["prior_knowledge"] = prior_facts
                            self._hydrate_challenge_from_facts(recovery_challenge, prior_facts)
                        if recovery.get("inputs", {}).get("task"):
                            recovery_challenge["current_task_description"] = recovery["inputs"]["task"]
                        result = self._run_selected_agent(recovery_challenge, target, [])
                    elif action == "run_tool":
                        result = self._run_selected_tool(challenge, target, [])
                    else:
                        result = None

                    if result:
                        history.append(result)
                        if result.get("steps"):
                            all_steps.extend([f"  [Recovery] {s}" for s in result["steps"]])
                        self._publish_result(result)
                        if result.get("artifacts"):
                            self._publish_knowledge(challenge_id, result["artifacts"])
                        if result.get("status") == "solved" or result.get("flag"):
                            final_result["status"] = "solved"
                            final_result["flag"] = result.get("flag")
                            all_steps.append("Challenge solved by LLM failure review recovery!")

            self.active_challenges.pop(challenge_id, None)
            final_result["steps"] = all_steps
            final_result["history"] = history
            
            self._cleanup_run_artifacts(history, all_steps)
            self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)
            self._record_solve_trace_best_effort(challenge, final_result)
            self._save_run_result_best_effort(final_result)
            return final_result

        except Exception as exc:
            self.update_status(AgentStatus.ERROR)
            final_result["status"] = "failed"
            final_result["steps"] = all_steps + [f"Coordinator error: {exc}"]
            self._cleanup_run_artifacts(history, final_result["steps"])
            self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)
            self.active_challenges.pop(challenge_id, None)
            return final_result
        finally:
            executor.shutdown(wait=False)
            if self.get_status() == AgentStatus.ERROR:
                self.update_status(AgentStatus.IDLE)

    def get_capabilities(self) -> List[str]:
        """Return coordinator capabilities."""
        return [
            "challenge_analysis",
            "agent_coordination",
            "strategy_formulation",
            "resource_management",
            "llm_routing",
        ]

    def _run_selected_agent(
        self,
        challenge: Dict[str, Any],
        target_agent_id: str,
        routing_steps: List[str],
    ) -> Dict[str, Any]:
        """
        Run a registered specialist agent selected by the reasoner.
        """
        agent = self.specialist_agents.get(target_agent_id) or self.support_agents.get(target_agent_id)

        if agent is None:
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "failed",
                "flag": None,
                "steps": routing_steps + [f"Selected agent '{target_agent_id}' is not registered."],
            }

        if agent.get_status() != AgentStatus.IDLE:
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "failed",
                "flag": None,
                "steps": routing_steps + [f"Selected agent '{target_agent_id}' is not idle."],
            }

        agent.assign_task(challenge)
        t0 = time.monotonic()
        try:
            result = agent.solve_challenge(challenge)

            result.setdefault("steps", [])
            result["steps"] = routing_steps + result["steps"]
            result["routing"] = {
                "selected_target": target_agent_id,
                "execution_type": "agent",
            }
            self._record_performance_outcome_best_effort(
                agent_id=target_agent_id,
                category=challenge.get("category", "misc"),
                challenge_id=challenge.get("id", "unknown"),
                status=result.get("status", "attempted"),
                duration_sec=time.monotonic() - t0,
            )
            return result
        finally:
            agent.complete_task()

    def _normalize_decision(
        self,
        action: str,
        target: str,
        challenge: Dict[str, Any],
        steps: List[str],
    ) -> tuple[str, str]:
        """Correct common LLM action/target mismatches before dispatch."""
        if action == "run_tool" and target in self._all_agent_ids():
            steps.append(f"Corrected decision: run_tool -> {target} should be run_agent.")
            return "run_agent", target

        tool_targets = {"browser_snapshot", "tony_htb_sql"}
        if action == "run_agent" and target in tool_targets:
            steps.append(f"Corrected decision: run_agent -> {target} should be run_tool.")
            return "run_tool", target

        description = (challenge.get("description") or "").lower()
        url = challenge.get("url") or challenge.get("target", {}).get("url")
        has_service = bool(url) or bool(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", description))
        mentions_jwt_web = any(term in description for term in ("jwt", "session", "token"))

        if (
            action == "run_agent"
            and target != "crypto_agent"
            and "crypto_agent" in self.specialist_agents
            and challenge.get("category") == "crypto"
            and has_service
            and self._has_rsa_time_capsule_source(challenge)
        ):
            steps.append("Corrected decision: RSA time-capsule TCP challenge should use crypto_agent.")
            return "run_agent", "crypto_agent"

        if (
            action == "run_agent"
            and target == "crypto_agent"
            and "web_agent" in self.specialist_agents
            and has_service
            and mentions_jwt_web
        ):
            steps.append("Corrected decision: live JWT/session web target should use web_agent.")
            return "run_agent", "web_agent"

        return action, target

    def _request_recovery_action_once(
        self,
        challenge: Dict[str, Any],
        analysis: ChallengeAnalysis,
        history: List[Dict[str, Any]],
        steps: List[str],
        already_attempted: bool,
    ) -> Optional[Dict[str, Any]]:
        """Ask an available LLM for one recovery action after a failed trace."""
        if already_attempted:
            return None

        category = str(challenge.get("category") or analysis.category_guess or "").lower()
        if category in {"pwn", "binary"} and os.getenv("CTF_AGENTS_ENABLE_PWN_LLM_RECOVERY") != "1":
            if history or any("[Exec]" in step or "[Async Result]" in step for step in steps):
                steps.append(
                    "Skipping pwn LLM recovery by default; set "
                    "CTF_AGENTS_ENABLE_PWN_LLM_RECOVERY=1 to enable it."
                )
            return None

        has_failed_trace = bool(history) or any(
            " failed:" in step
            or "failed" in step.lower()
            or "[Exec]" in step
            or "[Async Result]" in step
            for step in steps
        )
        if not has_failed_trace:
            return None

        suggest = getattr(self.reasoner, "suggest_recovery_action", None)
        if not callable(suggest) or not getattr(self.reasoner, "is_available", False):
            return None

        try:
            decision = suggest(challenge, analysis, history, steps)
        except Exception as exc:
            steps.append(f"LLM failure review errored: {exc}")
            return None
        if not isinstance(decision, dict):
            return None
        if decision.get("next_action", "stop") == "stop":
            return None
        if decision.get("target", "none") == "none":
            return None
        return decision

    @staticmethod
    def _has_rsa_time_capsule_source(challenge: Dict[str, Any]) -> bool:
        for raw_path in challenge.get("files", []):
            path = Path(str(raw_path))
            if path.suffix.lower() != ".py" or not path.exists():
                continue
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            compact = source.lower()
            if (
                "time_capsule" in compact
                and "pubkey" in compact
                and re.search(r"\bself\.e\s*=\s*(?:3|5|7|11)\b|\be\s*=\s*(?:3|5|7|11)\b", source)
            ):
                return True
        return False

    def _run_selected_tool(
        self,
        challenge: Dict[str, Any],
        target_tool: str,
        routing_steps: List[str],
    ) -> Dict[str, Any]:
        """
        Run a tool or adapter selected by the reasoner.
        """
        t0 = time.monotonic()
        if target_tool == "browser_snapshot":
            result = self._run_browser_snapshot(challenge, routing_steps)
        elif target_tool == "tony_htb_sql":
            result = self._run_tony_sql(challenge, routing_steps)
        else:
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "failed",
                "flag": None,
                "steps": routing_steps + [f"Unknown tool target '{target_tool}'."],
            }
        self._record_performance_outcome_best_effort(
            agent_id=target_tool,
            category=challenge.get("category", "misc"),
            challenge_id=challenge.get("id", "unknown"),
            status=result.get("status", "attempted"),
            duration_sec=time.monotonic() - t0,
        )
        return result

    def _record_performance_outcome_best_effort(
        self,
        agent_id: str,
        category: str,
        challenge_id: str,
        status: str,
        duration_sec: Optional[float] = None,
    ) -> None:
        """Record optional telemetry without letting SQLite issues abort solving."""
        if self.performance_tracker is None:
            return
        try:
            self.performance_tracker.record_outcome(
                agent_id=agent_id,
                category=category,
                challenge_id=challenge_id,
                status=status,
                duration_sec=duration_sec,
            )
        except Exception as exc:
            logger.warning(
                "Skipping performance telemetry for %s/%s: %s",
                challenge_id,
                agent_id,
                exc,
            )

    def _get_routing_hint_best_effort(self, category: str) -> Optional[tuple[str, float]]:
        if self.performance_tracker is None:
            return None
        try:
            return self.performance_tracker.get_routing_hint(category)
        except Exception as exc:
            logger.warning("Skipping performance hint for %s: %s", category, exc)
            return None

    @staticmethod
    def _create_performance_tracker() -> Optional[PerformanceTracker]:
        try:
            return PerformanceTracker()
        except Exception as exc:
            logger.warning("Performance telemetry unavailable: %s", exc)
            return None

    @staticmethod
    def _create_solve_trace_store() -> Optional[SolveTraceStore]:
        if os.getenv("PYTEST_CURRENT_TEST") and os.getenv("CTF_AGENTS_RECORD_TEST_TRACES") != "1":
            return None
        try:
            return SolveTraceStore()
        except Exception as exc:
            logger.warning("Solve trace store unavailable: %s", exc)
            return None

    def _record_solve_trace_best_effort(
        self,
        challenge: Dict[str, Any],
        result: Dict[str, Any],
    ) -> None:
        """Record solved challenge patterns for future retrieval/training."""
        if self.solve_trace_store is None:
            return
        try:
            self.solve_trace_store.record_solve(challenge, result)
        except Exception as exc:
            logger.warning(
                "Skipping solve trace recording for %s: %s",
                challenge.get("id", "unknown"),
                exc,
            )

    def _save_run_result_best_effort(self, result: Dict[str, Any]) -> None:
        """Persist run reports without allowing report I/O to change solve status."""
        if self.result_manager is None:
            return
        try:
            self.result_manager.save_run_result(result)
        except Exception as exc:
            logger.warning(
                "Skipping run result persistence for %s: %s",
                result.get("challenge_id", "unknown"),
                exc,
            )

    def _get_solve_trace_hints_best_effort(
        self,
        challenge: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Retrieve compact prior solve patterns without making solving depend on SQLite."""
        if self.solve_trace_store is None:
            return []
        try:
            return self.solve_trace_store.find_similar_patterns(challenge, limit=5)
        except Exception as exc:
            logger.warning(
                "Skipping solve trace retrieval for %s: %s",
                challenge.get("id", "unknown"),
                exc,
            )
            return []

    def _decision_from_trace_hints(
        self,
        trace_hints: List[Dict[str, Any]],
        history: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Turn a strong prior solve pattern into an advisory routing decision."""
        if not trace_hints:
            return None

        tried_targets = set()
        for entry in history:
            routing = entry.get("routing") or {}
            if routing.get("selected_target"):
                tried_targets.add(str(routing["selected_target"]))
            if entry.get("agent_id"):
                tried_targets.add(str(entry["agent_id"]))

        tool_targets = {"browser_snapshot", "tony_htb_sql"}
        for hint in trace_hints:
            if int(hint.get("similarity_score") or 0) < 6:
                continue
            target = hint.get("successful_target") or hint.get("successful_agent")
            if not target or target == self.agent_id or target in tried_targets:
                continue
            target = str(target)

            if target in self._all_agent_ids():
                action = "run_agent"
            elif target in tool_targets:
                action = "run_tool"
            else:
                continue

            shared = ", ".join(hint.get("shared_indicators") or [])
            return {
                "next_action": action,
                "target": target,
                "reasoning": (
                    "Trace memory matched a prior solved challenge "
                    f"({hint.get('challenge_id')}) with score "
                    f"{hint.get('similarity_score')}; trying {target}. "
                    f"Shared indicators: {shared}."
                ),
                "inputs": {
                    "task": (
                        "Use the prior solved route pattern as a hint, but derive "
                        "the current answer from current artifacts and live target."
                    )
                },
            }

        return None

    def _run_browser_snapshot(
        self,
        challenge: Dict[str, Any],
        routing_steps: List[str],
    ) -> Dict[str, Any]:
        """
        Run the browser snapshot tool against a challenge URL.
        """
        if self.browser_snapshot_tool is None:
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "failed",
                "flag": None,
                "steps": routing_steps + ["Browser snapshot tool is not configured."],
            }

        url = challenge.get("url") or challenge.get("target", {}).get("url")
        if not url:
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "failed",
                "flag": None,
                "steps": routing_steps + ["No URL provided for browser snapshot tool."],
            }

        # Assumes browser_snapshot_tool exposes a .run(url) method.
        snapshot_result = self.browser_snapshot_tool.run(url)

        return {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": "attempted",
            "flag": None,
            "steps": routing_steps + [f"Ran browser snapshot tool against {url}."],
            "artifacts": {
                "browser_snapshot": snapshot_result.to_dict() if hasattr(snapshot_result, 'to_dict') else snapshot_result,
            },
            "routing": {
                "selected_target": "browser_snapshot",
                "execution_type": "tool",
            },
        }

    def _run_tony_sql(
        self,
        challenge: Dict[str, Any],
        routing_steps: List[str],
    ) -> Dict[str, Any]:
        """
        Run Tony's HTB SQL adapter.
        """
        if self.tony_sql_adapter is None:
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "failed",
                "flag": None,
                "steps": routing_steps + ["Tony SQL adapter is not configured."],
            }

        # Assumes adapter exposes solve(challenge, routing_steps=...)
        result = self.tony_sql_adapter.solve(challenge, routing_steps=routing_steps)
        result.setdefault("routing", {})
        result["routing"].update({
            "selected_target": "tony_htb_sql",
            "execution_type": "tool",
        })
        return result

    def _checkpoint_progress(
        self,
        checkpoint_dir: Path,
        challenge_id: str,
        history: List[Dict[str, Any]],
        all_steps: List[str],
    ) -> None:
        """Write a checkpoint JSON file so recovery is possible after a crash."""
        try:
            checkpoint_dir.mkdir(parents=True, exist_ok=True)
            checkpoint_path = safe_checkpoint_path(checkpoint_dir, challenge_id)
            checkpoint = {
                "challenge_id": challenge_id,
                "timestamp": datetime.now().isoformat(),
                "iterations": len([
                    step for step in all_steps
                    if step.startswith("Iteration ") and " decision: " in step
                ]),
                "history": history,
                "steps": all_steps,
            }
            with open(checkpoint_path, "w") as f:
                json.dump(checkpoint, f, indent=2)
            logger.debug("Checkpoint written to %s", checkpoint_path)
        except Exception as exc:
            logger.warning("Failed to write checkpoint for %s: %s", challenge_id, exc)

    def _load_checkpoint(
        self,
        checkpoint_dir: Path,
        challenge_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Load a prior checkpoint if one exists for this challenge."""
        checkpoint_path = safe_checkpoint_path(checkpoint_dir, challenge_id)
        if not checkpoint_path.exists():
            logger.info("No checkpoint found for %s; starting fresh.", challenge_id)
            return None

        try:
            with open(checkpoint_path) as f:
                checkpoint = json.load(f)
            if not isinstance(checkpoint, dict):
                logger.warning("Ignoring malformed checkpoint for %s.", challenge_id)
                return None
            return checkpoint
        except Exception as exc:
            logger.warning("Failed to load checkpoint for %s: %s", challenge_id, exc)
            return None

    def list_registered_agents(self) -> Dict[str, List[str]]:
        """
        Helpful for debugging.
        """
        return {
            "specialists": list(self.specialist_agents.keys()),
            "support": list(self.support_agents.keys()),
        }

    def _all_agent_ids(self) -> set[str]:
        return set(self.specialist_agents) | set(self.support_agents)

    def _direct_initial_agent(
        self,
        challenge: Dict[str, Any],
        analysis: Optional[ChallengeAnalysis] = None,
    ) -> Optional[str]:
        category = str(challenge.get("category") or "").lower()
        direct_routes = {
            "web": "web_agent",
            "crypto": "crypto_agent",
            "cryptography": "crypto_agent",
            "reverse": "reverse_agent",
            "reversing": "reverse_agent",
            "rev": "reverse_agent",
            "forensics": "forensics_agent",
            "pwn": "pwn_agent",
            "binary": "pwn_agent",
            "hardware": "hardware_agent",
            "blockchain": "blockchain_agent",
            "secure_coding": "secure_coding_agent",
            "secure-coding": "secure_coding_agent",
            "log": "log_agent",
            "networking": "networking_agent",
            "network": "networking_agent",
            "osint": "osint_agent",
            "coding": "coding_agent",
        }
        target = direct_routes.get(category)
        if analysis is not None:
            recommended = (analysis.recommended_target or "none").strip()
            source_backed_web = (
                target == "web_agent"
                and recommended == "browser_snapshot"
                and bool(challenge.get("files"))
            )
            if source_backed_web:
                recommended = target
            if recommended not in {"", "none", target}:
                return None
        if target in self.specialist_agents or target in self.support_agents:
            return target
        return None

    @staticmethod
    def _hydrate_challenge_from_facts(challenge: Dict[str, Any], facts: List[Dict[str, Any]]) -> None:
        if challenge.get("url"):
            return
        for fact in reversed(facts):
            if fact.get("key") == "docker_target_url" and fact.get("value"):
                challenge["url"] = fact["value"]
                return

    def _cleanup_run_artifacts(self, history: List[Dict[str, Any]], steps: List[str]) -> None:
        seen_containers = set()
        for result in history:
            artifacts = result.get("artifacts") or {}
            container_id = artifacts.get("docker_container_id")
            if not container_id or container_id in seen_containers:
                continue
            seen_containers.add(container_id)
            agent = self.support_agents.get(result.get("agent_id"))
            cleanup = getattr(agent, "cleanup_artifacts", None)
            if callable(cleanup):
                cleanup(artifacts, steps)

    def _publish_result(self, result: Dict[str, Any]) -> None:
        """Broadcast an agent/tool result so other agents can react."""
        safe_result = redact_sensitive_data(result)
        self.broker.publish(Message(
            message_id=str(uuid.uuid4()),
            message_type=MessageType.RESULT_REPORT,
            sender=self.agent_id,
            recipient="*",
            timestamp=datetime.now(),
            priority=MessagePriority.NORMAL,
            payload={"result": safe_result},
        ))

    def _publish_knowledge(self, challenge_id: str, artifacts: Dict[str, Any]) -> None:
        """Share discovered artifacts and store them in the KnowledgeStore."""
        safe_artifacts = redact_sensitive_data(artifacts)
        # 1. Store in KnowledgeStore for persistence
        for key, value in safe_artifacts.items():
            self.knowledge_store.add_fact(
                challenge_id=challenge_id,
                agent_id=self.agent_id,
                key=key,
                value=value,
                metadata={"timestamp": datetime.now().isoformat()}
            )

        # 2. Broadcast via broker for immediate reaction
        self.broker.publish(Message(
            message_id=str(uuid.uuid4()),
            message_type=MessageType.KNOWLEDGE_SHARE,
            sender=self.agent_id,
            recipient="*",
            timestamp=datetime.now(),
            priority=MessagePriority.HIGH,
            payload={"challenge_id": challenge_id, "artifacts": safe_artifacts},
        ))

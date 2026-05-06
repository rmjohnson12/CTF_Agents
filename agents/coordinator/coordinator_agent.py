"""
Coordinator Agent

Main orchestrator for the CTF solving workflow.
Uses an LLM-backed decision layer (with heuristic fallback) to decide
which specialist agent or tool to run next.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from agents.base_agent import BaseAgent, AgentType, AgentStatus
from core.communication.message import Message, MessageType, MessagePriority
from core.communication.message_broker import MessageBroker
from core.decision_engine.llm_reasoner import LLMReasoner, ChallengeAnalysis
from core.utils.result_manager import ResultManager
from core.task_manager.task_queue import TaskQueue
from core.task_manager.task import Task, TaskPriority
from core.knowledge_base.knowledge_store import KnowledgeStore
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
    ):
        ks = knowledge_store or KnowledgeStore()
        super().__init__(agent_id, AgentType.COORDINATOR, knowledge_store=ks)

        self.specialist_agents: Dict[str, BaseAgent] = {}
        self.support_agents: Dict[str, BaseAgent] = {}
        self.active_challenges: Dict[str, Dict[str, Any]] = {}

        self.browser_snapshot_tool = browser_snapshot_tool
        self.tony_sql_adapter = tony_sql_adapter
        self.reasoner = LLMReasoner(client=llm_client)
        self.max_iterations = max_iterations
        self.result_manager = ResultManager()
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
        challenge_id = challenge.get("id", "unknown_challenge")
        self.active_challenges[challenge_id] = challenge
        checkpoint_dir = Path("logs/checkpoints")
        checkpoint_dir.mkdir(parents=True, exist_ok=True)

        initial_analysis_obj = self.reasoner.analyze_challenge(challenge)
        initial_analysis = self._analysis_to_dict(challenge, initial_analysis_obj)
        checkpoint = self._load_checkpoint(checkpoint_dir, challenge_id) if resume else None
        history: List[Dict[str, Any]] = checkpoint.get("history", []) if checkpoint else []
        
        if checkpoint:
            all_steps = checkpoint.get("steps", [])
            all_steps.append(f"Resuming from checkpoint with {len(history)} prior result(s).")
            start_iteration = int(checkpoint.get("iterations", len(history)))
        else:
            all_steps = [
                f"Initial category guess: {initial_analysis['category']}",
                f"Initial confidence: {initial_analysis['confidence']:.2f}",
            ]
            start_iteration = 0

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

        def record_completed_future(f, step_prefix: str) -> Optional[Dict[str, Any]]:
            task_info = futures.pop(f)
            task_id = task_info["task_id"]
            try:
                result = f.result()
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
                    return final_result
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
                        self.result_manager.save_run_result(completed_result)
                        return completed_result

                # Fetch prior knowledge for this challenge to inform the next decision
                prior_facts = self.knowledge_store.get_facts(challenge_id=challenge_id)
                challenge_with_knowledge = challenge.copy()
                if prior_facts:
                    challenge_with_knowledge["prior_knowledge"] = prior_facts
                    all_steps.append(f"  [Knowledge] Retrieved {len(prior_facts)} fact(s) from storage.")

                decision = self.reasoner.choose_next_action(
                    challenge_with_knowledge, 
                    initial_analysis_obj,
                    history
                )

                action = decision.get("next_action", "stop")
                target = decision.get("target", "none")
                reasoning = decision.get("reasoning", "No reasoning provided.")

                if action == "stop":
                    if not futures:
                        all_steps.append("Reasoner requested to stop.")
                        self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)
                        break
                    else:
                        all_steps.append("Reasoner requested to stop, but tasks are still running...")
                        self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)
                        continue

                if any(info["action"] == action and info["target"] == target for info in futures.values()):
                    all_steps.append(f"Waiting for in-flight task: {action} -> {target}")
                    self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)
                    continue

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
                        
                    if decision.get("inputs", {}).get("task"):
                        agent_challenge['current_task_description'] = decision["inputs"]["task"]
                    
                    f = executor.submit(self._run_selected_agent, agent_challenge, target, [])
                    futures[f] = {"task_id": task_id, "action": action, "target": target}
                elif action == "run_tool":
                    f = executor.submit(self._run_selected_tool, challenge, target, [])
                    futures[f] = {"task_id": task_id, "action": action, "target": target}
                else:
                    all_steps.append(f"Unknown action: {action}")
                    self.task_queue.fail_task(task_id, f"Unknown action: {action}")
                    self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)
                    continue

                just_done, _ = concurrent.futures.wait([f], timeout=0.01)
                if f in just_done:
                    completed_result = record_completed_future(f, "Exec")
                    if completed_result is not None:
                        completed_result["steps"] = all_steps
                        completed_result["history"] = history
                        self.active_challenges.pop(challenge_id, None)
                        self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)
                        self.result_manager.save_run_result(completed_result)
                        return completed_result

                self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)

            # Wait for any remaining tasks
            if futures:
                all_steps.append(f"Waiting for {len(futures)} remaining tasks...")
                done, _ = concurrent.futures.wait(futures.keys(), timeout=30)
                for f in done:
                    record_completed_future(f, "Exec")

            self.active_challenges.pop(challenge_id, None)
            final_result["steps"] = all_steps
            final_result["history"] = history
            
            self._checkpoint_progress(checkpoint_dir, challenge_id, history, all_steps)
            self.result_manager.save_run_result(final_result)
            return final_result

        except Exception as exc:
            self.update_status(AgentStatus.ERROR)
            final_result["status"] = "failed"
            final_result["steps"] = all_steps + [f"Coordinator error: {exc}"]
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
        agent = self.specialist_agents.get(target_agent_id)

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
        try:
            result = agent.solve_challenge(challenge)

            result.setdefault("steps", [])
            result["steps"] = routing_steps + result["steps"]
            result["routing"] = {
                "selected_target": target_agent_id,
                "execution_type": "agent",
            }
            return result
        finally:
            agent.complete_task()

    def _run_selected_tool(
        self,
        challenge: Dict[str, Any],
        target_tool: str,
        routing_steps: List[str],
    ) -> Dict[str, Any]:
        """
        Run a tool or adapter selected by the reasoner.
        """
        if target_tool == "browser_snapshot":
            return self._run_browser_snapshot(challenge, routing_steps)

        if target_tool == "tony_htb_sql":
            return self._run_tony_sql(challenge, routing_steps)

        return {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": "failed",
            "flag": None,
            "steps": routing_steps + [f"Unknown tool target '{target_tool}'."],
        }

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
            checkpoint_path = checkpoint_dir / f"{challenge_id}.json"
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
        checkpoint_path = checkpoint_dir / f"{challenge_id}.json"
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

    def _publish_result(self, result: Dict[str, Any]) -> None:
        """Broadcast an agent/tool result so other agents can react."""
        self.broker.publish(Message(
            message_id=str(uuid.uuid4()),
            message_type=MessageType.RESULT_REPORT,
            sender=self.agent_id,
            recipient="*",
            timestamp=datetime.now(),
            priority=MessagePriority.NORMAL,
            payload={"result": result},
        ))

    def _publish_knowledge(self, challenge_id: str, artifacts: Dict[str, Any]) -> None:
        """Share discovered artifacts and store them in the KnowledgeStore."""
        # 1. Store in KnowledgeStore for persistence
        for key, value in artifacts.items():
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
            payload={"challenge_id": challenge_id, "artifacts": artifacts},
        ))

"""
Coordinator Agent

Main orchestrator for the CTF solving workflow.
Uses an LLM-backed decision layer (with heuristic fallback) to decide
which specialist agent or tool to run next.
"""

from __future__ import annotations

from typing import Dict, Any, List, Optional

from agents.base_agent import BaseAgent, AgentType, AgentStatus
from core.decision_engine.llm_reasoner import LLMReasoner


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
    ):
        super().__init__(agent_id, AgentType.COORDINATOR)

        self.specialist_agents: Dict[str, BaseAgent] = {}
        self.support_agents: Dict[str, BaseAgent] = {}
        self.active_challenges: Dict[str, Dict[str, Any]] = {}

        self.browser_snapshot_tool = browser_snapshot_tool
        self.tony_sql_adapter = tony_sql_adapter
        self.reasoner = LLMReasoner(client=llm_client)
        self.max_iterations = max_iterations

    def register_agent(self, agent: BaseAgent):
        """Register a specialist or support agent with the coordinator."""
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

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Coordinate the solving of a challenge in an iterative loop.

        Flow:
        1. Analyze challenge with reasoner (initial triage)
        2. Loop:
           a. Choose next action based on history
           b. Execute action
           c. Record result in history
           d. Check for completion
        3. Return aggregated result
        """
        challenge_id = challenge.get("id", "unknown_challenge")
        self.active_challenges[challenge_id] = challenge

        initial_analysis = self.analyze_challenge(challenge)
        history: List[Dict[str, Any]] = []
        
        all_steps = [
            f"Initial category guess: {initial_analysis['category']}",
            f"Initial confidence: {initial_analysis['confidence']:.2f}",
        ]

        final_result = {
            "challenge_id": challenge_id,
            "agent_id": self.agent_id,
            "status": "attempted",
            "flag": None,
            "steps": all_steps,
            "iterations": 0,
        }

        try:
            for i in range(self.max_iterations):
                final_result["iterations"] = i + 1
                
                decision = self.reasoner.choose_next_action(
                    challenge, 
                    self.reasoner.analyze_challenge(challenge),
                    history
                )

                action = decision.get("next_action", "stop")
                target = decision.get("target", "none")
                reasoning = decision.get("reasoning", "No reasoning provided.")

                all_steps.append(f"Iteration {i+1} reasoning: {reasoning}")
                all_steps.append(f"Iteration {i+1} decision: {action} -> {target}")

                if action == "stop":
                    all_steps.append("Reasoner requested to stop.")
                    break

                result = None
                if action == "run_agent":
                    result = self._run_selected_agent(challenge, target, [])
                elif action == "run_tool":
                    result = self._run_selected_tool(challenge, target, [])
                else:
                    all_steps.append(f"Unknown action: {action}")
                    break

                if result:
                    history.append(result)
                    if result.get("steps"):
                        all_steps.extend([f"  [Exec] {s}" for s in result["steps"]])
                    
                    if result.get("status") == "solved" or result.get("flag"):
                        final_result["status"] = "solved"
                        final_result["flag"] = result.get("flag")
                        all_steps.append("Challenge solved!")
                        break
                else:
                    all_steps.append(f"Failed to execute {action} against {target}")
                    break

            self.active_challenges.pop(challenge_id, None)
            final_result["steps"] = all_steps
            final_result["history"] = history
            return final_result

        except Exception as exc:
            self.update_status(AgentStatus.ERROR)
            final_result["status"] = "failed"
            final_result["steps"] = all_steps + [f"Coordinator error: {exc}"]
            self.active_challenges.pop(challenge_id, None)
            return final_result
        finally:
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
                "browser_snapshot": snapshot_result,
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

    def list_registered_agents(self) -> Dict[str, List[str]]:
        """
        Helpful for debugging.
        """
        return {
            "specialists": list(self.specialist_agents.keys()),
            "support": list(self.support_agents.keys()),
        }
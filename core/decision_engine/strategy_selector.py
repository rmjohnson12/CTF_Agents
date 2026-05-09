"""
StrategySelector — decides the next agent or tool action for a challenge.

Encapsulates the heuristic next-action logic and optionally incorporates
PerformanceTracker history to bias routing toward agents with a proven
solve record for the current challenge category.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.decision_engine.classifier import ChallengeAnalysis


# Minimum historical success-rate required before the tracker's suggestion
# overrides the classifier's recommendation.
_PERFORMANCE_BIAS_THRESHOLD = 0.60


class StrategySelector:
    """
    Translates a ChallengeAnalysis into a concrete next-action dict.

    When a PerformanceTracker is provided the selector will substitute its
    routing recommendation with the historically best-performing agent if
    that agent's success rate exceeds _PERFORMANCE_BIAS_THRESHOLD.
    """

    def __init__(self, performance_tracker: Optional[Any] = None) -> None:
        self.performance_tracker = performance_tracker

    def select_next(
        self,
        challenge: Dict[str, Any],
        analysis: ChallengeAnalysis,
        history: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Return the next action dict.

        Keys: next_action, target, reasoning, inputs
        """
        decision = self._heuristic_select(challenge, analysis, history)

        # Performance-based override: if we have enough history pointing to a
        # better agent than the classifier chose, swap it in.
        if (
            self.performance_tracker is not None
            and decision.get("next_action") == "run_agent"
        ):
            hint = self.performance_tracker.get_routing_hint(analysis.category_guess)
            if hint:
                best_agent, rate = hint
                current_target = decision.get("target", "")
                if rate >= _PERFORMANCE_BIAS_THRESHOLD and best_agent != current_target:
                    decision = {
                        "next_action": "run_agent",
                        "target": best_agent,
                        "reasoning": (
                            f"Performance tracker recommends '{best_agent}' "
                            f"({rate:.0%} solve rate for '{analysis.category_guess}') "
                            f"over classifier choice '{current_target}'."
                        ),
                        "inputs": decision.get("inputs", {}),
                    }

        return decision

    # ------------------------------------------------------------------
    # Internal heuristic
    # ------------------------------------------------------------------

    def _heuristic_select(
        self,
        challenge: Dict[str, Any],
        analysis: ChallengeAnalysis,
        history: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        last_result = history[-1] if history else {}
        last_agent = last_result.get("agent_id")
        last_status = last_result.get("status")
        last_artifacts = last_result.get("artifacts", {})

        # Docker agent finished — hand off its URL to web_agent
        if last_agent == "docker_agent" and last_artifacts.get("docker_target_url"):
            return {
                "next_action": "run_agent",
                "target": "web_agent",
                "reasoning": "Docker challenge is running locally. Handing mapped localhost URL to web_agent.",
                "inputs": {"url": last_artifacts["docker_target_url"]},
            }

        # Crypto script pivot: crypto agent failed but a .py file is present
        files = challenge.get("files", [])
        has_script = any(f.endswith(".py") for f in files)
        if has_script and any(h.get("agent_id") == "crypto_agent" for h in history):
            return {
                "next_action": "run_agent",
                "target": "coding_agent",
                "reasoning": (
                    "Crypto agent could not solve it directly. "
                    "Pivoting to coding agent to analyze the provided script."
                ),
                "inputs": {
                    "task": "Analyze the encryption script and implement a decryption routine for the output."
                },
            }

        # Browser snapshot found a login form — try automated bypass
        if last_artifacts and "browser_snapshot" in last_artifacts:
            forms = last_artifacts["browser_snapshot"].get("forms", [])
            has_login = any(
                "user" in str(f).lower() or "pass" in str(f).lower() for f in forms
            )
            if has_login and last_status != "solved":
                return {
                    "next_action": "run_agent",
                    "target": "coding_agent",
                    "reasoning": (
                        "A login form was discovered in the browser snapshot. "
                        "Pivoting to coding_agent to attempt an automated login bypass."
                    ),
                    "inputs": {
                        "task": "Attempt SQLi login bypass or default credentials on the discovered form."
                    },
                }

        # Avoid repeating the same failed agent / tool unless a new hint was added
        has_hint = "User Hint:" in challenge.get("description", "")
        if not has_hint:
            if last_agent == analysis.recommended_target and last_status != "solved":
                return {
                    "next_action": "stop",
                    "target": "none",
                    "reasoning": (
                        f"Specialist {last_agent} already attempted this task and did not "
                        "find a solution. Stopping to prevent infinite loop."
                    ),
                    "inputs": {},
                }

            last_target = last_result.get("routing", {}).get("selected_target")
            if (
                last_target == "browser_snapshot"
                and analysis.recommended_target == "browser_snapshot"
            ):
                return {
                    "next_action": "stop",
                    "target": "none",
                    "reasoning": "Browser snapshot already performed. No further information gathered. Stopping.",
                    "inputs": {},
                }

        # Route to the classified target
        _AGENT_TARGETS = {
            "pwn_agent", "crypto_agent", "coding_agent", "forensics_agent",
            "reverse_agent", "osint_agent", "log_agent", "web_agent",
            "docker_agent", "recon_agent", "networking_agent",
        }
        target = analysis.recommended_target

        if target in _AGENT_TARGETS:
            return {
                "next_action": "run_agent",
                "target": target,
                "reasoning": analysis.reasoning,
                "inputs": {},
            }

        if target == "browser_snapshot":
            return {
                "next_action": "run_tool",
                "target": "browser_snapshot",
                "reasoning": analysis.reasoning,
                "inputs": {
                    "url": challenge.get("url")
                    or challenge.get("target", {}).get("url", "")
                },
            }

        if target == "tony_htb_sql":
            return {
                "next_action": "run_tool",
                "target": "tony_htb_sql",
                "reasoning": "SQL injection likely.",
                "inputs": {
                    "url": challenge.get("url")
                    or challenge.get("target", {}).get("url", "")
                },
            }

        return {
            "next_action": "stop",
            "target": "none",
            "reasoning": "No confident next step.",
            "inputs": {},
        }

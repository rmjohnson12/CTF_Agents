"""Bounded sequential runner for challenge campaigns."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

from core.campaign.attempt_store import AttemptStore
from core.campaign.providers import ChallengeProvider


@dataclass
class CampaignSummary:
    campaign_id: str
    queued: int = 0
    solved: int = 0
    failed: int = 0
    skipped: int = 0
    results: List[Dict[str, Any]] = field(default_factory=list)
    benchmark_rows: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        total_duration = sum(float(row["duration_sec"]) for row in self.benchmark_rows)
        total_iterations = sum(int(row["iterations"]) for row in self.benchmark_rows)
        total_tools = sum(int(row["tools_invoked"]) for row in self.benchmark_rows)
        total_fallbacks = sum(int(row["fallback_count"]) for row in self.benchmark_rows)
        attempted = self.solved + self.failed
        return {
            "campaign_id": self.campaign_id,
            "queued": self.queued,
            "attempted": attempted,
            "solved": self.solved,
            "failed": self.failed,
            "skipped": self.skipped,
            "solve_rate": (self.solved / attempted) if attempted else 0.0,
            "runtime_sec": round(total_duration, 6),
            "iterations": total_iterations,
            "tools_invoked": total_tools,
            "fallback_count": total_fallbacks,
            "challenges": self.benchmark_rows,
        }

    def to_markdown(self) -> str:
        report = self.to_dict()
        lines = [
            "# CTF_Agents Benchmark Summary",
            "",
            f"- Campaign: `{self.campaign_id}`",
            f"- Solve rate: {report['solved']}/{report['attempted']} ({report['solve_rate']:.1%})",
            f"- Runtime: {report['runtime_sec']:.3f}s",
            f"- Iterations: {report['iterations']}",
            f"- Tool invocations: {report['tools_invoked']}",
            f"- Fallbacks: {report['fallback_count']}",
            "",
            "| Challenge | Status | Agent | Runtime | Iterations | Tools | Fallbacks | Failure reason |",
            "|---|---|---|---:|---:|---:|---:|---|",
        ]
        for row in self.benchmark_rows:
            reason = str(row.get("failure_reason") or "").replace("|", "\\|").replace("\n", " ")
            lines.append(
                f"| {row['challenge_id']} | {row['status']} | {row.get('agent_selected') or ''} | "
                f"{row['duration_sec']:.3f}s | {row['iterations']} | {row['tools_invoked']} | "
                f"{row['fallback_count']} | {reason} |"
            )
        return "\n".join(lines) + "\n"


class CampaignRunner:
    """Run a filtered challenge queue while respecting persisted retry limits."""

    def __init__(
        self,
        provider: ChallengeProvider,
        solve: Callable[[Dict[str, Any]], Dict[str, Any]],
        attempt_store: Optional[AttemptStore] = None,
    ):
        self.provider = provider
        self.solve = solve
        self.attempt_store = attempt_store or AttemptStore()

    def run(
        self,
        categories: Optional[Set[str]] = None,
        limit: Optional[int] = None,
        max_attempts: int = 2,
        retry_solved: bool = False,
    ) -> CampaignSummary:
        configuration = {
            "categories": sorted(categories or []),
            "limit": limit,
            "max_attempts": max_attempts,
            "retry_solved": retry_solved,
        }
        campaign_id = self.attempt_store.start_campaign(self.provider.name, configuration)
        summary = CampaignSummary(campaign_id=campaign_id)
        try:
            challenges = list(self.provider.list_challenges())
            if categories:
                challenges = [c for c in challenges if c.get("category") in categories]
            if limit is not None:
                challenges = challenges[: max(0, limit)]
            summary.queued = len(challenges)

            for challenge in challenges:
                challenge_id = str(challenge.get("id", "unknown"))
                solved_before = self.attempt_store.is_solved(self.provider.name, challenge_id)
                attempts = self.attempt_store.attempt_count(self.provider.name, challenge_id)
                if (solved_before and not retry_solved) or attempts >= max_attempts:
                    summary.skipped += 1
                    continue

                started_at = time.time()
                try:
                    result = self.solve(dict(challenge))
                except Exception as exc:
                    result = {
                        "challenge_id": challenge_id,
                        "status": "failed",
                        "error": f"{type(exc).__name__}: {exc}",
                        "steps": ["Campaign solver raised an exception."],
                        "history": [],
                    }
                finished_at = time.time()
                self.attempt_store.record_attempt(
                    campaign_id,
                    self.provider.name,
                    challenge,
                    result,
                    started_at,
                    finished_at,
                )
                summary.results.append(result)
                history = list(result.get("history") or [])
                selected_agents = [
                    (entry.get("routing") or {}).get("selected_target") or entry.get("agent_id")
                    for entry in history
                    if ((entry.get("routing") or {}).get("execution_type") or "agent") == "agent"
                ]
                tool_count = sum(
                    1 for entry in history
                    if (entry.get("routing") or {}).get("execution_type") == "tool"
                )
                routing_summary = result.get("routing_summary") or {}
                summary.benchmark_rows.append({
                    "challenge_id": challenge_id,
                    "category": challenge.get("category"),
                    "status": str(result.get("status") or "failed"),
                    "duration_sec": round(max(0.0, finished_at - started_at), 6),
                    "iterations": int(result.get("iterations") or 0),
                    "tools_invoked": tool_count,
                    "agent_selected": (
                        selected_agents[-1] if selected_agents
                        else routing_summary.get("selected_target") or result.get("agent_id")
                    ),
                    "fallback_count": max(0, len(history) - 1),
                    "failure_reason": (
                        AttemptStore._failure_reason(result)
                        if result.get("status") != "solved" else None
                    ),
                })
                if result.get("status") == "solved":
                    summary.solved += 1
                else:
                    summary.failed += 1
        finally:
            self.attempt_store.finish_campaign(campaign_id)
        return summary

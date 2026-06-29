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
                self.attempt_store.record_attempt(
                    campaign_id,
                    self.provider.name,
                    challenge,
                    result,
                    started_at,
                )
                summary.results.append(result)
                if result.get("status") == "solved":
                    summary.solved += 1
                else:
                    summary.failed += 1
        finally:
            self.attempt_store.finish_campaign(campaign_id)
        return summary

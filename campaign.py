"""Run a bounded campaign across local CTF challenge definitions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from core.campaign import AttemptStore, CampaignRunner
from core.campaign.providers import LocalChallengeProvider
from main import build_coordinator


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run a queue of authorized CTF challenges.")
    parser.add_argument("source", help="Challenge JSON, directory, or benchmark manifest.")
    parser.add_argument("--category", action="append", dest="categories", help="Category filter; repeatable.")
    parser.add_argument("--limit", type=int, help="Maximum number of queued challenges.")
    parser.add_argument("--max-attempts", type=int, default=2, help="Lifetime attempt cap per challenge.")
    parser.add_argument("--max-iterations", type=int, default=5, help="Coordinator iteration cap per challenge.")
    parser.add_argument("--retry-solved", action="store_true", help="Run challenges already solved by a prior campaign.")
    parser.add_argument("--db", default="logs/attempts.db", help="Attempt-ledger SQLite path.")
    parser.add_argument("--json-out", help="Write the machine-readable benchmark summary to this path.")
    parser.add_argument("--markdown-out", help="Write a Markdown benchmark summary to this path.")
    args = parser.parse_args(argv)

    if args.max_attempts < 1:
        parser.error("--max-attempts must be at least 1")

    coordinator = build_coordinator(max_iterations=args.max_iterations)
    runner = CampaignRunner(
        LocalChallengeProvider(args.source),
        solve=coordinator.solve_challenge,
        attempt_store=AttemptStore(args.db),
    )
    summary = runner.run(
        categories=set(args.categories or []),
        limit=args.limit,
        max_attempts=args.max_attempts,
        retry_solved=args.retry_solved,
    )
    payload = summary.to_dict()
    if args.json_out:
        output_path = Path(args.json_out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if args.markdown_out:
        output_path = Path(args.markdown_out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(summary.to_markdown(), encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0 if summary.failed == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

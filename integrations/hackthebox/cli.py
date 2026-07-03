"""Command-line entry point for HTB challenge automation.

Examples
--------
Dry-run (default; no live download/spawn/submit — only a read-only listing):

    python -m integrations.hackthebox.cli --category web --max 3 --dry-run

Real run (must pass --execute), writing a report:

    python -m integrations.hackthebox.cli --category web --max 3 --execute \\
        --output reports/htb_results.md

Submission is never automatic — it also requires --submit AND --execute.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime, timezone
from typing import List

from .auth import DEFAULT_SESSION_FILE, authenticate
from .client import HTBClient
from .config import HTBConfig
from .challenge_runner import ChallengeRunner, filter_challenges
from .errors import HTBAuthError, HTBError
from .models import Challenge, HTBCredentials, RunReport
from .reporting import write_reports

logger = logging.getLogger("htb")

# Git-ignored files the CLI will load credentials from, in priority order.
# Real (already-exported) environment variables always win over file contents.
_ENV_FILES = (".htb.env", "htb.env", ".env")


def _load_env_files() -> List[str]:
    """Load HTB creds from a local git-ignored env file if present.

    Returns the list of files that were loaded (for logging). Existing
    environment variables are never overridden, so `export HTB_TOKEN=...` wins.
    """
    try:
        from dotenv import load_dotenv
    except Exception:  # pragma: no cover - python-dotenv is a project dependency
        return []
    loaded: List[str] = []
    for name in _ENV_FILES:
        if os.path.isfile(name) and load_dotenv(name, override=False):
            loaded.append(name)
    return loaded


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m integrations.hackthebox.cli",
        description="Automate Hack The Box challenges for your own authenticated account.",
    )
    p.add_argument("--category", help="Filter by challenge category (e.g. web, crypto, pwn).")
    p.add_argument("--difficulty", help="Filter by difficulty text (e.g. Easy, Medium).")
    p.add_argument("--name", help="Target a specific challenge by (case-insensitive) name substring.")
    p.add_argument("--id", type=int, default=None, dest="challenge_id", help="Target a specific challenge id.")
    p.add_argument("--max", type=int, default=None, dest="max_count", help="Max challenges to select.")

    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Plan only; no live actions (default).")
    mode.add_argument("--execute", action="store_true", help="Perform the real run (download/spawn/solve).")

    p.add_argument("--submit", action="store_true", help="Submit found HTB-format flags (requires --execute).")
    p.add_argument("--submit-difficulty", type=int, default=50, help="Post-solve difficulty rating 10-100.")

    p.add_argument("--include-retired", action="store_true", help="Include retired challenges.")
    p.add_argument("--include-solved", action="store_true", help="Include already-solved challenges.")
    p.add_argument("--include-locked", action="store_true", help="Include locked/unavailable challenges.")
    p.add_argument("--no-start", action="store_true", help="Do not spawn challenge instances.")
    p.add_argument("--no-stop", action="store_true", help="Leave spawned instances running.")

    p.add_argument("--output", default="", help="Report path (Markdown). JSON sidecar written alongside.")
    p.add_argument("--report-dir", default="reports", help="Directory for the default report path.")
    p.add_argument("--session-file", default=DEFAULT_SESSION_FILE, help="Local session cache file.")
    p.add_argument("--browser-fallback", action="store_true", help="Allow the Playwright UI fallback (opt-in).")
    p.add_argument("--solver-timeout", type=float, default=600.0, help="Per-challenge solver timeout (seconds).")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging.")
    return p


def main(argv: List[str] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    loaded = _load_env_files()
    if loaded:
        logger.info("Loaded credentials from %s (values never logged).", ", ".join(loaded))

    # Default to the safe mode: dry-run unless --execute is explicitly given.
    dry_run = not args.execute
    if args.submit and dry_run:
        logger.info("--submit ignored in dry-run mode; use --execute to submit.")

    config = HTBConfig()
    creds = HTBCredentials.from_env()

    try:
        auth = authenticate(creds, config, cache_path=args.session_file)
    except HTBAuthError as exc:
        logger.error("Authentication failed: %s", exc)
        return 2

    client = HTBClient(auth.token, config=config)

    # Naming a specific challenge is an explicit request for it: don't silently
    # drop it just because it's retired or already solved, and search retired too.
    targeted = bool(args.name or args.challenge_id)
    include_retired = args.include_retired or targeted
    include_solved = args.include_solved or targeted

    try:
        challenges = _discover(client, include_retired=include_retired)
    except HTBError as exc:
        logger.error("Could not list challenges: %s", exc)
        return 3

    selected = filter_challenges(
        challenges,
        category=args.category,
        difficulty=args.difficulty,
        name_contains=args.name,
        challenge_id=args.challenge_id,
        include_retired=include_retired,
        include_solved=include_solved,
        include_locked=args.include_locked,
        max_count=args.max_count,
    )
    if targeted and not selected:
        logger.error(
            "No challenge matched %s. It may be spelled differently, locked for your "
            "account, or not returned by the list endpoint.",
            args.name or f"id={args.challenge_id}",
        )
        return 4

    mode_label = "DRY-RUN (no live actions)" if dry_run else "LIVE"
    logger.info("%s | %d challenge(s) selected of %d discovered.", mode_label, len(selected), len(challenges))
    for ch in selected:
        logger.info("  - #%s %s [%s/%s]%s", ch.id, ch.name, ch.category, ch.difficulty,
                    "  (needs instance)" if ch.needs_instance else "")

    runner = ChallengeRunner(client, config, solver_timeout_seconds=args.solver_timeout)
    started_at = datetime.now(timezone.utc)
    attempts = runner.run(
        selected,
        dry_run=dry_run,
        do_start=not args.no_start,
        submit=args.submit and not dry_run,
        submit_difficulty=args.submit_difficulty,
        stop_started=not args.no_stop,
    )

    report = RunReport(
        timestamp=started_at.isoformat(),
        user={"id": auth.user.get("id"), "name": auth.user.get("name")},
        filters={
            "category": args.category,
            "difficulty": args.difficulty,
            "name": args.name,
            "id": args.challenge_id,
            "max": args.max_count,
            "include_retired": include_retired,
            "include_solved": include_solved,
            "include_locked": args.include_locked,
        },
        dry_run=dry_run,
        submit_enabled=args.submit and not dry_run,
        attempts=attempts,
        duration_seconds=(datetime.now(timezone.utc) - started_at).total_seconds(),
    )

    md_path, json_path = write_reports(report, output_path=args.output, report_dir=args.report_dir)
    logger.info("Report written: %s", md_path)
    logger.info("JSON report:    %s", json_path)

    solved = sum(1 for a in attempts if a.candidate_flags)
    logger.info("Done. %d/%d challenge(s) produced candidate flags.", solved, len(attempts))
    return 0


def _discover(client: HTBClient, *, include_retired: bool) -> List[Challenge]:
    challenges = client.list_challenges(retired=False)
    if include_retired:
        try:
            challenges = challenges + client.list_challenges(retired=True)
        except HTBError as exc:
            logger.warning("Could not list retired challenges: %s", exc)
    return challenges


if __name__ == "__main__":
    raise SystemExit(main())

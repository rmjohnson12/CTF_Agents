"""Render run results to Markdown and a machine-readable JSON sidecar.

Reports may contain candidate flags and challenge metadata, so the default
output directory (``reports/``) is git-ignored. Nothing secret (tokens,
cookies, passwords) is ever written here.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Tuple

from .models import ChallengeAttempt, RunReport

DEFAULT_REPORT_DIR = "reports"


def _safe_stamp(timestamp: str) -> str:
    return re.sub(r"[^0-9A-Za-z]+", "", timestamp) or "run"


def default_report_path(report: RunReport, report_dir: str = DEFAULT_REPORT_DIR) -> str:
    return str(Path(report_dir) / f"htb_results_{_safe_stamp(report.timestamp)}.md")


def render_markdown(report: RunReport) -> str:
    lines = [
        "# Hack The Box automation run",
        "",
        f"- **Timestamp:** {report.timestamp}",
        f"- **User:** {report.user.get('name', 'unknown')} (id={report.user.get('id', 'unknown')})",
        f"- **Mode:** {'DRY-RUN' if report.dry_run else 'LIVE'}"
        + ("  |  submission ENABLED" if report.submit_enabled else "  |  submission disabled"),
        f"- **Filters:** {json.dumps(report.filters)}",
        f"- **Duration:** {report.duration_seconds:.1f}s",
        f"- **Challenges attempted:** {len(report.attempts)}",
        "",
    ]
    if report.errors:
        lines += ["## Run-level errors", ""]
        lines += [f"- {e}" for e in report.errors]
        lines.append("")

    for attempt in report.attempts:
        lines.extend(_render_attempt(attempt))

    return "\n".join(lines).rstrip() + "\n"


def _render_attempt(attempt: ChallengeAttempt) -> list:
    ch = attempt.challenge
    lines = [
        f"## {ch.name}  (#{ch.id})",
        "",
        f"- Category: {ch.category}  |  Difficulty: {ch.difficulty}"
        + (f"  |  Points: {ch.points}" if ch.points is not None else ""),
        f"- Retired: {ch.retired}  |  Solved: {ch.solved}  |  Needs instance: {ch.needs_instance}"
        f"  |  Has download: {ch.has_download}",
    ]
    if ch.description:
        lines.append(f"- Description: {ch.description[:500]}")
    if attempt.work_dir:
        lines.append(f"- Work dir: `{attempt.work_dir}`")
    lines.append(f"- Started/spawned: {attempt.started}")
    if attempt.spawn:
        lines.append(f"- Target: `{attempt.spawn.target}`  (status: {attempt.spawn.status})")
    if attempt.downloaded_files:
        lines.append(f"- Files downloaded: {len(attempt.downloaded_files)}")
        lines += [f"    - `{f}`" for f in attempt.downloaded_files[:20]]
    lines.append(f"- Solver status: {attempt.solver_status}")
    if attempt.solver_steps:
        lines.append("- Solver steps:")
        lines += [f"    - {s}" for s in attempt.solver_steps[:30]]
    if attempt.candidate_flags:
        lines.append("- **Candidate flags:**")
        lines += [f"    - `{c}`" for c in attempt.candidate_flags]
    else:
        lines.append("- Candidate flags: none")
    lines.append(f"- Submitted: {attempt.submitted}")
    if attempt.submission_result:
        lines.append(f"- Submission result: {attempt.submission_result}")
    if attempt.error:
        lines.append(f"- **Error:** {attempt.error}")
    lines.append(f"- Duration: {attempt.duration_seconds:.1f}s")
    lines.append("")
    return lines


def write_reports(report: RunReport, output_path: str = "", report_dir: str = DEFAULT_REPORT_DIR) -> Tuple[str, str]:
    """Write the Markdown report and a JSON sidecar. Returns (md_path, json_path)."""
    md_path = Path(output_path) if output_path else Path(default_report_path(report, report_dir))
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_markdown(report), encoding="utf-8")

    json_path = md_path.with_suffix(".json")
    json_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return str(md_path), str(json_path)

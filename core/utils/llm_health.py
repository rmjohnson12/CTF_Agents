"""Shared helpers for surfacing LLM-availability problems to the operator.

A silent fall-through to heuristic-only routing looks like "the agents suddenly
got dumb": only challenges with hard-coded solve paths keep working. These
helpers make that state impossible to miss regardless of entrypoint.
"""
from __future__ import annotations

import sys
from typing import Any, Dict, Optional, TextIO


def llm_run_degraded(llm_summary: Optional[Dict[str, Any]]) -> bool:
    """True if a finished run had no working LLM (disabled, or zero successes)."""
    if not llm_summary:
        return False
    degraded = bool(llm_summary.get("degraded"))
    no_successful_calls = (
        llm_summary.get("calls", 0) > 0 and llm_summary.get("successful_calls", 0) == 0
    )
    return degraded or no_successful_calls


def warn_if_llm_degraded(
    llm_summary: Optional[Dict[str, Any]],
    stream: Optional[TextIO] = None,
) -> None:
    """Print a prominent banner if the run fell back to heuristic-only mode."""
    if not llm_run_degraded(llm_summary):
        return
    stream = stream or sys.stderr
    reason = (llm_summary or {}).get("disabled_reason") or "no LLM provider responded successfully"
    providers = ", ".join((llm_summary or {}).get("configured_providers") or []) or "none"
    print(
        "\n"
        "============================================================\n"
        "  WARNING: LLM reasoning was UNAVAILABLE this run.\n"
        f"  Reason           : {reason}\n"
        f"  Configured chain : {providers}\n"
        "  The coordinator ran in HEURISTIC-ONLY mode, which can only\n"
        "  solve challenges that have hard-coded solve paths. Fix the\n"
        "  provider (quota/keys/model) and re-run. See check_setup.py.\n"
        "============================================================",
        file=stream,
    )

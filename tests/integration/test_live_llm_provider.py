"""Opt-in live LLM smoke tests.

These tests intentionally call the configured provider. They are skipped by
default so CI and normal local unit runs stay deterministic and cost-free.
Run with:

    CTF_AGENTS_RUN_LIVE_LLM_TESTS=1 pytest tests/integration/test_live_llm_provider.py
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict

import pytest
from dotenv import load_dotenv


pytestmark = pytest.mark.live_llm


def _live_reasoner_or_skip(monkeypatch):
    if os.getenv("CTF_AGENTS_RUN_LIVE_LLM_TESTS") != "1":
        pytest.skip("set CTF_AGENTS_RUN_LIVE_LLM_TESTS=1 to call the live LLM provider")

    # tests/conftest.py strips LLM env vars for deterministic tests. Undo that
    # fixture's env changes for this opt-in file, then load the root .env.
    monkeypatch.undo()
    load_dotenv(override=False)
    os.environ.setdefault("LLM_TIMEOUT_SECONDS", "20")

    from core.decision_engine.llm_reasoner import LLMReasoner

    reasoner = LLMReasoner()
    if not reasoner.is_available:
        pytest.skip("no live LLM provider configured")
    return reasoner


def _extract_json_object(text: str) -> Dict[str, Any]:
    cleaned = text.strip().replace("```json", "").replace("```", "").strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", cleaned, re.S)
        if not match:
            raise
        return json.loads(match.group(0))


def test_live_llm_raw_call_returns_requested_json(monkeypatch):
    reasoner = _live_reasoner_or_skip(monkeypatch)
    provider = reasoner.provider
    model = reasoner.model

    raw = reasoner._call_llm(
        'Return ONLY this JSON object and no prose: {"ok": true, "answer": "pong"}'
    )
    if not raw:
        pytest.fail(
            "live LLM provider returned no content; check the configured key, "
            f"provider={provider!r}, model={model!r}, "
            f"post_call_provider={reasoner.provider!r}"
        )
    data = _extract_json_object(raw)

    assert data.get("ok") is True
    assert str(data.get("answer", "")).lower() == "pong"


def test_live_llm_recovery_review_returns_action_schema(monkeypatch):
    reasoner = _live_reasoner_or_skip(monkeypatch)
    provider = reasoner.provider
    model = reasoner.model

    from core.decision_engine.llm_reasoner import ChallengeAnalysis

    decision = reasoner.suggest_recovery_action(
        {
            "id": "live_llm_recovery_probe",
            "category": "web",
            "description": (
                "Web challenge failed to produce a flag, but the web agent "
                "downloaded an unexplored ELF binary artifact."
            ),
            "files": ["/tmp/artifact.bin"],
        },
        ChallengeAnalysis(
            category_guess="web",
            confidence=0.72,
            reasoning="web target with downloaded artifact",
            recommended_target="web_agent",
            recommended_action="run_agent",
            detected_indicators=["url", "downloaded_artifact"],
        ),
        [
            {
                "agent_id": "web_agent",
                "status": "attempted",
                "flag": None,
                "routing": {
                    "selected_target": "web_agent",
                    "execution_type": "agent",
                },
            }
        ],
        [
            "Iteration 1 decision: run_agent -> web_agent",
            "  [Exec] Found downloaded binary artifact: /tmp/artifact.bin",
            "  [Exec] Web checks found no flag.",
        ],
    )

    assert decision["next_action"] in {"run_agent", "run_tool", "stop"}
    assert decision["target"]
    assert isinstance(decision["reasoning"], str)
    assert decision["reasoning"]
    assert "unavailable" not in decision["reasoning"].lower()
    if "invalid json" in decision["reasoning"].lower():
        pytest.fail(
            "live LLM recovery returned no parseable JSON; check the configured key, "
            f"provider={provider!r}, model={model!r}, "
            f"post_call_provider={reasoner.provider!r}"
        )

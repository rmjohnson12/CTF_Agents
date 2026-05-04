"""
Tests for the LLM reasoner fixes:
  - f-string bug: prompts must contain actual challenge data
  - model default changed from gpt-5.4 -> gpt-4o
  - NVAPI_KEY auto-selects NVIDIA NIM
  - OPENAI_API_KEY fallback
  - no keys -> heuristic fallback (client is None)
  - _call_llm uses chat.completions.create
"""

import json
from dataclasses import asdict
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from core.decision_engine.llm_reasoner import (
    LLMReasoner,
    ChallengeAnalysis,
    _NVIDIA_NIM_BASE_URL,
    _NVIDIA_DEFAULT_MODEL,
)


SAMPLE_CHALLENGE = {
    "id": "test_001",
    "name": "Test Challenge",
    "description": "A mysterious cipher awaits",
    "hints": ["think ROT13"],
    "tags": ["crypto"],
    "files": [],
    "metadata": {},
}


# ── prompt content (f-string fix) ────────────────────────────────────

def test_analysis_prompt_contains_challenge_data():
    """_build_analysis_prompt must embed the actual challenge JSON, not a literal."""
    reasoner = LLMReasoner(client=None)
    prompt = reasoner._build_analysis_prompt(SAMPLE_CHALLENGE)

    assert "test_001" in prompt, "challenge id missing from prompt"
    assert "mysterious cipher" in prompt, "challenge description missing from prompt"
    assert "{json.dumps" not in prompt, "f-string was not evaluated (literal brace escape bug)"


def test_next_action_prompt_contains_challenge_and_history():
    """_build_next_action_prompt must embed challenge, analysis, and history JSON."""
    reasoner = LLMReasoner(client=None)
    analysis = ChallengeAnalysis(
        category_guess="crypto",
        confidence=0.9,
        reasoning="looks encrypted",
        recommended_target="crypto_agent",
        recommended_action="run_agent",
        detected_indicators=["cipher_terms"],
    )
    history = [{"agent_id": "crypto_agent", "status": "attempted", "flag": None}]

    prompt = reasoner._build_next_action_prompt(SAMPLE_CHALLENGE, analysis, history)

    assert "test_001" in prompt, "challenge id missing from next-action prompt"
    assert "crypto_agent" in prompt, "analysis target missing from next-action prompt"
    assert "attempted" in prompt, "history missing from next-action prompt"
    assert "{json.dumps" not in prompt, "f-string escape bug in next-action prompt"


# ── model defaults ────────────────────────────────────────────────────

def test_default_model_is_gpt4o_when_no_keys(monkeypatch):
    monkeypatch.delenv("NVAPI_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    reasoner = LLMReasoner()
    assert reasoner.model == "none"
    assert reasoner.client is None


def test_explicit_client_uses_provided_model():
    mock_client = MagicMock()
    reasoner = LLMReasoner(client=mock_client, model="my-model")
    assert reasoner.model == "my-model"
    assert reasoner.client is mock_client


def test_explicit_client_defaults_to_gpt4o():
    mock_client = MagicMock()
    reasoner = LLMReasoner(client=mock_client)
    assert reasoner.model == "gpt-4o"


# ── NVAPI_KEY auto-configuration ──────────────────────────────────────

def test_nvapi_key_selects_nvidia_nim(monkeypatch):
    monkeypatch.setenv("NVAPI_KEY", "nvapi-fake-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with patch("core.decision_engine.llm_reasoner.OpenAI") as MockOpenAI:
        MockOpenAI.return_value = MagicMock()
        reasoner = LLMReasoner()

    call_kwargs = MockOpenAI.call_args.kwargs
    assert call_kwargs["api_key"] == "nvapi-fake-key"
    assert call_kwargs["base_url"] == _NVIDIA_NIM_BASE_URL
    assert reasoner.model == _NVIDIA_DEFAULT_MODEL


def test_nvapi_key_overrides_openai_key(monkeypatch):
    monkeypatch.setenv("NVAPI_KEY", "nvapi-fake-key")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake-openai")

    with patch("core.decision_engine.llm_reasoner.OpenAI") as MockOpenAI:
        MockOpenAI.return_value = MagicMock()
        reasoner = LLMReasoner()

    call_kwargs = MockOpenAI.call_args.kwargs
    assert call_kwargs["base_url"] == _NVIDIA_NIM_BASE_URL, \
        "NVAPI_KEY should take priority over OPENAI_API_KEY"


def test_openai_key_fallback(monkeypatch):
    monkeypatch.delenv("NVAPI_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake-openai")

    with patch("core.decision_engine.llm_reasoner.OpenAI") as MockOpenAI:
        MockOpenAI.return_value = MagicMock()
        reasoner = LLMReasoner()

    call_kwargs = MockOpenAI.call_args.kwargs
    assert call_kwargs["api_key"] == "sk-fake-openai"
    assert "base_url" not in call_kwargs, "OpenAI path must not set NVIDIA base_url"
    assert reasoner.model == "gpt-4o"


# ── _call_llm uses chat.completions ───────────────────────────────────

def test_call_llm_uses_chat_completions():
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content="some response"))]
    )
    reasoner = LLMReasoner(client=mock_client)
    result = reasoner._call_llm("hello")

    mock_client.chat.completions.create.assert_called_once()
    call_kwargs = mock_client.chat.completions.create.call_args.kwargs
    assert call_kwargs["model"] == "gpt-4o"
    assert call_kwargs["messages"] == [{"role": "user", "content": "hello"}]
    assert result == "some response"


def test_call_llm_falls_back_on_exception():
    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = Exception("API down")
    reasoner = LLMReasoner(client=mock_client)
    result = reasoner._call_llm("hello")
    assert result == ""


def test_call_llm_handles_none_content():
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content=None))]
    )
    reasoner = LLMReasoner(client=mock_client)
    result = reasoner._call_llm("hello")
    assert result == ""


# ── heuristic fallback still works ───────────────────────────────────

def test_heuristic_fallback_when_no_client():
    reasoner = LLMReasoner(client=None)
    analysis = reasoner.analyze_challenge(SAMPLE_CHALLENGE)
    assert analysis.category_guess == "crypto"
    assert analysis.recommended_target == "crypto_agent"


def test_analyze_falls_back_to_heuristic_on_bad_json():
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content="not valid json {{{"))]
    )
    reasoner = LLMReasoner(client=mock_client)
    analysis = reasoner.analyze_challenge(SAMPLE_CHALLENGE)
    # Should not raise; heuristic kicks in
    assert analysis.category_guess in (
        "crypto", "web", "reverse", "forensics", "misc", "osint", "log", "unknown"
    )

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
    _ANTHROPIC_DEFAULT_MODEL,
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


@pytest.fixture(autouse=True)
def clear_llm_env(monkeypatch):
    """Keep provider-selection tests independent from the developer's shell."""
    for key in (
        "LLM_PROVIDER",
        "NVAPI_KEY",
        "NGC_API_KEY",
        "NVIDIA_MODEL",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_MODEL",
        "OPENAI_API_KEY",
        "OPENAI_MODEL",
    ):
        monkeypatch.delenv(key, raising=False)


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

    with patch("core.decision_engine.llm_reasoner.OpenAI") as MockOpenAI:
        MockOpenAI.return_value = MagicMock()
        reasoner = LLMReasoner()

    call_kwargs = MockOpenAI.call_args.kwargs
    assert call_kwargs["api_key"] == "nvapi-fake-key"
    assert call_kwargs["base_url"] == _NVIDIA_NIM_BASE_URL
    assert reasoner.model == _NVIDIA_DEFAULT_MODEL


def test_ngc_api_key_alias_selects_nvidia_nim(monkeypatch):
    monkeypatch.setenv("NGC_API_KEY", "ngc-fake-key")

    with patch("core.decision_engine.llm_reasoner.OpenAI") as MockOpenAI:
        MockOpenAI.return_value = MagicMock()
        reasoner = LLMReasoner()

    call_kwargs = MockOpenAI.call_args.kwargs
    assert call_kwargs["api_key"] == "ngc-fake-key"
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
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake-openai")

    with patch("core.decision_engine.llm_reasoner.OpenAI") as MockOpenAI:
        MockOpenAI.return_value = MagicMock()
        reasoner = LLMReasoner()

    call_kwargs = MockOpenAI.call_args.kwargs
    assert call_kwargs["api_key"] == "sk-fake-openai"
    assert "base_url" not in call_kwargs, "OpenAI path must not set NVIDIA base_url"
    assert reasoner.model == "gpt-4o"


def test_anthropic_key_fallback(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")

    with patch("core.decision_engine.llm_reasoner.Anthropic") as MockAnthropic:
        MockAnthropic.return_value = MagicMock()
        reasoner = LLMReasoner()

    call_kwargs = MockAnthropic.call_args.kwargs
    assert call_kwargs["api_key"] == "sk-ant-fake"
    assert reasoner.provider == "anthropic"
    assert reasoner.model == _ANTHROPIC_DEFAULT_MODEL


def test_provider_preference_selects_anthropic_over_nvidia(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("NVAPI_KEY", "nvapi-fake-key")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")

    with patch("core.decision_engine.llm_reasoner.Anthropic") as MockAnthropic, \
            patch("core.decision_engine.llm_reasoner.OpenAI") as MockOpenAI:
        MockAnthropic.return_value = MagicMock()
        reasoner = LLMReasoner()

    MockAnthropic.assert_called_once()
    MockOpenAI.assert_not_called()
    assert reasoner.provider == "anthropic"


def test_provider_preference_falls_back_to_nvidia_when_anthropic_missing(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("NVAPI_KEY", "nvapi-fake-key")

    with patch("core.decision_engine.llm_reasoner.OpenAI") as MockOpenAI, \
            patch("core.decision_engine.llm_reasoner.Anthropic") as MockAnthropic:
        MockOpenAI.return_value = MagicMock()
        reasoner = LLMReasoner()

    MockAnthropic.assert_not_called()
    MockOpenAI.assert_called_once()
    assert reasoner.provider == "nvidia"
    assert reasoner.model == _NVIDIA_DEFAULT_MODEL


def test_provider_override_selects_custom_anthropic_model(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "claude")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-test-model")

    with patch("core.decision_engine.llm_reasoner.Anthropic") as MockAnthropic:
        MockAnthropic.return_value = MagicMock()
        reasoner = LLMReasoner()

    assert reasoner.provider == "anthropic"
    assert reasoner.model == "claude-test-model"


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


def test_call_llm_uses_anthropic_messages():
    mock_client = MagicMock()
    mock_client.messages.create.return_value = MagicMock(
        content=[MagicMock(text="claude response")]
    )
    reasoner = LLMReasoner(
        client=mock_client,
        model="claude-test-model",
        provider="anthropic",
    )
    result = reasoner._call_llm("hello")

    mock_client.messages.create.assert_called_once()
    call_kwargs = mock_client.messages.create.call_args.kwargs
    assert call_kwargs["model"] == "claude-test-model"
    assert call_kwargs["max_tokens"] == 2000
    assert call_kwargs["messages"] == [{"role": "user", "content": "hello"}]
    assert result == "claude response"


def test_call_llm_retries_retryable_exception_before_success():
    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = [
        TimeoutError("temporary timeout"),
        MagicMock(choices=[MagicMock(message=MagicMock(content="recovered"))]),
    ]
    reasoner = LLMReasoner(client=mock_client)

    with patch("core.decision_engine.llm_reasoner.time.sleep") as sleep:
        result = reasoner._call_llm("hello")

    assert result == "recovered"
    assert mock_client.chat.completions.create.call_count == 2
    sleep.assert_called_once_with(1.0)


def test_call_llm_exhausts_retryable_errors_without_final_sleep():
    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = TimeoutError("still down")
    reasoner = LLMReasoner(client=mock_client)

    with patch("core.decision_engine.llm_reasoner.time.sleep") as sleep:
        result = reasoner._call_llm("hello")

    assert result == ""
    assert mock_client.chat.completions.create.call_count == 3
    assert [call.args[0] for call in sleep.call_args_list] == [1.0, 2.0]


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

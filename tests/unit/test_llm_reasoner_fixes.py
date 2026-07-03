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
    _OLLAMA_DEFAULT_BASE_URL,
    _OLLAMA_DEFAULT_MODEL,
    _GOOGLE_DEFAULT_MODEL,
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
        "NVAPI_KEYS",
        "NVAPI_KEY",
        "NGC_API_KEY",
        "NVIDIA_MODEL",
        "OLLAMA_API_KEY",
        "OLLAMA_BASE_URL",
        "OLLAMA_MODEL",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_MODEL",
        "OPENAI_API_KEY",
        "OPENAI_MODEL",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_MODEL",
        "GOOGLE_GENAI_USE_VERTEXAI",
        "GOOGLE_GENAI_USE_ENTERPRISE",
        "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_PROJECT_ID",
        "GOOGLE_CLOUD_LOCATION",
        "GOOGLE_LOCATION",
        "LLM_TIMEOUT_SECONDS",
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


def test_recovery_prompt_contains_failed_trace():
    reasoner = LLMReasoner(client=None)
    analysis = ChallengeAnalysis(
        category_guess="web",
        confidence=0.8,
        reasoning="looks web",
        recommended_target="web_agent",
        recommended_action="run_agent",
        detected_indicators=["url"],
    )
    history = [{"agent_id": "web_agent", "status": "attempted", "flag": None}]
    steps = ["Iteration 1 decision: run_agent -> web_agent", "  [Exec] no flag found"]

    prompt = reasoner._build_recovery_prompt(SAMPLE_CHALLENGE, analysis, history, steps)

    assert "stalled CTF agent workflow" in prompt
    assert "web_agent" in prompt
    assert "no flag found" in prompt


def test_suggest_recovery_action_parses_valid_json(monkeypatch):
    mock_client = MagicMock()
    reasoner = LLMReasoner(client=mock_client)
    monkeypatch.setattr(
        reasoner,
        "_call_llm",
        lambda prompt: json.dumps({
            "next_action": "run_agent",
            "target": "coding_agent",
            "reasoning": "Generate a focused parser from the failed trace.",
            "inputs": {"task": "Parse the artifact bytes for a hidden flag."},
        }),
    )
    analysis = ChallengeAnalysis("misc", 0.6, "unknown", "none", "stop", [])

    decision = reasoner.suggest_recovery_action(
        SAMPLE_CHALLENGE,
        analysis,
        [{"agent_id": "web_agent", "status": "attempted"}],
        ["failed"],
    )

    assert decision["next_action"] == "run_agent"
    assert decision["target"] == "coding_agent"
    assert decision["inputs"]["task"].startswith("Parse")


def test_synthesize_runtime_tool_parses_declarative_proposal(monkeypatch):
    mock_client = MagicMock()
    reasoner = LLMReasoner(client=mock_client)
    proposal = {
        "name": "probe_api",
        "hypothesis": "A discovered endpoint exposes encoded output.",
        "evidence": ["Trace contains /api/result."],
        "operations": [
            {"op": "http_request", "url": "/api/result", "save_as": "response"}
        ],
    }
    monkeypatch.setattr(reasoner, "_call_llm", lambda prompt: json.dumps(proposal))

    result = reasoner.synthesize_runtime_tool(
        SAMPLE_CHALLENGE,
        [{"status": "attempted"}],
        ["Found /api/result"],
        ["http_request"],
    )

    assert result == proposal


def test_suggest_recovery_action_rejects_sql_without_sql_evidence(monkeypatch):
    mock_client = MagicMock()
    reasoner = LLMReasoner(client=mock_client)
    monkeypatch.setattr(
        reasoner,
        "_call_llm",
        lambda prompt: json.dumps({
            "next_action": "run_tool",
            "target": "tony_htb_sql",
            "reasoning": "Try SQL because this is a web challenge.",
            "inputs": {},
        }),
    )
    analysis = ChallengeAnalysis("web", 0.8, "web URL", "web_agent", "run_agent", ["url"])

    decision = reasoner.suggest_recovery_action(
        {"id": "web_artifact", "category": "web", "description": "Asset portal leaked a backup."},
        analysis,
        [{"agent_id": "web_agent", "status": "attempted"}],
        [
            "Header artifact hints: https://target/assets/bak/file_backup.sys",
            "Decoded certutil/PEM-style block: header='OpenSCAD Model'",
            "Detected binary STL artifact",
        ],
    )

    assert decision["next_action"] == "stop"
    assert decision["target"] == "none"
    assert "Rejected SQL recovery suggestion" in decision["reasoning"]


def test_suggest_recovery_action_stops_without_client():
    reasoner = LLMReasoner(client=None)
    analysis = ChallengeAnalysis("misc", 0.6, "unknown", "none", "stop", [])

    decision = reasoner.suggest_recovery_action(SAMPLE_CHALLENGE, analysis, [], [])

    assert decision["next_action"] == "stop"
    assert decision["target"] == "none"


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
    assert call_kwargs["timeout"] == 20.0
    assert reasoner.model == _NVIDIA_DEFAULT_MODEL


def test_llm_timeout_seconds_configures_sdk_clients(monkeypatch):
    monkeypatch.setenv("NVAPI_KEY", "nvapi-fake-key")
    monkeypatch.setenv("LLM_TIMEOUT_SECONDS", "3.5")

    with patch("core.decision_engine.llm_reasoner.OpenAI") as MockOpenAI:
        MockOpenAI.return_value = MagicMock()
        reasoner = LLMReasoner()

    call_kwargs = MockOpenAI.call_args.kwargs
    assert call_kwargs["timeout"] == 3.5
    assert reasoner.timeout_seconds == 3.5


def test_invalid_llm_timeout_seconds_uses_default(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake-openai")
    monkeypatch.setenv("LLM_TIMEOUT_SECONDS", "eventually")

    with patch("core.decision_engine.llm_reasoner.OpenAI") as MockOpenAI:
        MockOpenAI.return_value = MagicMock()
        reasoner = LLMReasoner()

    call_kwargs = MockOpenAI.call_args.kwargs
    assert call_kwargs["timeout"] == 20.0
    assert reasoner.timeout_seconds == 20.0


def test_nvapi_keys_selects_first_nvidia_key(monkeypatch):
    monkeypatch.setenv("NVAPI_KEYS", "nvapi-first, nvapi-second")

    with patch("core.decision_engine.llm_reasoner.OpenAI") as MockOpenAI:
        MockOpenAI.return_value = MagicMock()
        reasoner = LLMReasoner()

    call_kwargs = MockOpenAI.call_args.kwargs
    assert call_kwargs["api_key"] == "nvapi-first"
    assert reasoner.provider == "nvidia"
    assert reasoner._nvidia_keys == ["nvapi-first", "nvapi-second"]


def test_nvapi_key_singular_accepts_comma_separated_fallbacks(monkeypatch):
    monkeypatch.setenv("NVAPI_KEY", "nvapi-first, nvapi-second")

    with patch("core.decision_engine.llm_reasoner.OpenAI") as MockOpenAI:
        MockOpenAI.return_value = MagicMock()
        reasoner = LLMReasoner()

    call_kwargs = MockOpenAI.call_args.kwargs
    assert call_kwargs["api_key"] == "nvapi-first"
    assert reasoner.provider == "nvidia"
    assert reasoner._nvidia_keys == ["nvapi-first", "nvapi-second"]


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


def test_google_api_key_selects_google_genai(monkeypatch):
    monkeypatch.setenv("GOOGLE_API_KEY", "google-fake-key")
    fake_genai = MagicMock()
    fake_genai.Client.return_value = MagicMock()

    with patch("core.decision_engine.llm_reasoner.importlib.import_module", return_value=fake_genai), \
            patch("core.decision_engine.llm_reasoner.OpenAI") as MockOpenAI:
        reasoner = LLMReasoner()

    fake_genai.Client.assert_called_once_with(
        api_key="google-fake-key",
        http_options={"timeout": 20000},
    )
    MockOpenAI.assert_not_called()
    assert reasoner.provider == "google"
    assert reasoner.model == _GOOGLE_DEFAULT_MODEL


def test_gemini_provider_alias_uses_custom_google_model(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-fake-key")
    monkeypatch.setenv("GOOGLE_MODEL", "gemini-test-model")
    fake_genai = MagicMock()
    fake_genai.Client.return_value = MagicMock()

    with patch("core.decision_engine.llm_reasoner.importlib.import_module", return_value=fake_genai):
        reasoner = LLMReasoner()

    fake_genai.Client.assert_called_once_with(
        api_key="gemini-fake-key",
        http_options={"timeout": 20000},
    )
    assert reasoner.provider == "google"
    assert reasoner.model == "gemini-test-model"


def test_google_cloud_adc_path_uses_project_and_location(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "google")
    monkeypatch.setenv("GOOGLE_GENAI_USE_VERTEXAI", "true")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "ctf-project")
    monkeypatch.setenv("GOOGLE_CLOUD_LOCATION", "us-central1")
    fake_genai = MagicMock()
    fake_genai.Client.return_value = MagicMock()

    with patch("core.decision_engine.llm_reasoner.importlib.import_module", return_value=fake_genai):
        reasoner = LLMReasoner()

    fake_genai.Client.assert_called_once_with(
        vertexai=True,
        project="ctf-project",
        location="us-central1",
        http_options={"timeout": 20000},
    )
    assert reasoner.provider == "google"
    assert reasoner.model == _GOOGLE_DEFAULT_MODEL


def test_ollama_provider_uses_openai_compatible_client(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")

    with patch("core.decision_engine.llm_reasoner.OpenAI") as MockOpenAI:
        MockOpenAI.return_value = MagicMock()
        reasoner = LLMReasoner()

    call_kwargs = MockOpenAI.call_args.kwargs
    assert call_kwargs["api_key"] == "ollama"
    assert call_kwargs["base_url"] == "http://localhost:11434/v1"
    assert call_kwargs["timeout"] == 20.0
    assert reasoner.provider == "ollama"
    assert reasoner.model == "qwen2.5-coder:7b"


def test_ollama_provider_uses_defaults(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "ollama")

    with patch("core.decision_engine.llm_reasoner.OpenAI") as MockOpenAI:
        MockOpenAI.return_value = MagicMock()
        reasoner = LLMReasoner()

    call_kwargs = MockOpenAI.call_args.kwargs
    assert call_kwargs["api_key"] == "ollama"
    assert call_kwargs["base_url"] == _OLLAMA_DEFAULT_BASE_URL
    assert reasoner.provider == "ollama"
    assert reasoner.model == _OLLAMA_DEFAULT_MODEL


def test_local_provider_alias_selects_ollama(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "local")

    with patch("core.decision_engine.llm_reasoner.OpenAI") as MockOpenAI:
        MockOpenAI.return_value = MagicMock()
        reasoner = LLMReasoner()

    call_kwargs = MockOpenAI.call_args.kwargs
    assert call_kwargs["base_url"] == _OLLAMA_DEFAULT_BASE_URL
    assert reasoner.provider == "ollama"


def test_ollama_provider_overrides_cloud_keys(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("NVAPI_KEY", "nvapi-fake-key")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake-openai")

    with patch("core.decision_engine.llm_reasoner.OpenAI") as MockOpenAI:
        MockOpenAI.return_value = MagicMock()
        reasoner = LLMReasoner()

    call_kwargs = MockOpenAI.call_args.kwargs
    assert call_kwargs["base_url"] == _OLLAMA_DEFAULT_BASE_URL
    assert call_kwargs["api_key"] == "ollama"
    assert reasoner.provider == "ollama"


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


def test_provider_none_disables_llm_even_when_keys_exist(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "none")
    monkeypatch.setenv("NVAPI_KEYS", "nvapi-first,nvapi-second")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake-openai")

    with patch("core.decision_engine.llm_reasoner.OpenAI") as MockOpenAI, \
            patch("core.decision_engine.llm_reasoner.Anthropic") as MockAnthropic:
        reasoner = LLMReasoner()

    MockOpenAI.assert_not_called()
    MockAnthropic.assert_not_called()
    assert reasoner.client is None
    assert reasoner.provider == "none"


def test_nvidia_key_rotation_on_429(monkeypatch):
    monkeypatch.setenv("NVAPI_KEYS", "nvapi-first,nvapi-second")

    first_client = MagicMock()
    second_client = MagicMock()
    first_client.chat.completions.create.side_effect = Exception("429 rate limit")
    second_client.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content="recovered with fallback key"))]
    )

    with patch("core.decision_engine.llm_reasoner.OpenAI", side_effect=[first_client, second_client]):
        reasoner = LLMReasoner()
        result = reasoner._call_llm("hello")

    assert result == "recovered with fallback key"
    assert reasoner._nvidia_key_index == 1
    first_client.chat.completions.create.assert_called_once()
    second_client.chat.completions.create.assert_called_once()


def test_google_429_fails_over_to_configured_nvidia_provider(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "google")
    monkeypatch.setenv("GOOGLE_API_KEY", "google-fake-key")
    monkeypatch.setenv("NVAPI_KEY", "nvapi-fallback")

    google_client = MagicMock()
    google_client.models.generate_content.side_effect = Exception("429 quota exhausted")
    nvidia_client = MagicMock()
    nvidia_client.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content="recovered through nvidia"))]
    )

    def configure_google(reasoner, _api_key):
        reasoner.client = google_client

    with patch.object(LLMReasoner, "_configure_google_client", configure_google), \
            patch("core.decision_engine.llm_reasoner.OpenAI", return_value=nvidia_client):
        reasoner = LLMReasoner()
        result = reasoner._call_llm("hello")

    assert result == "recovered through nvidia"
    assert reasoner.provider == "nvidia"
    assert reasoner.model == _NVIDIA_DEFAULT_MODEL
    assert reasoner.runtime_summary()["failovers"] == 1
    assert reasoner.runtime_summary()["last_successful_provider"] == "nvidia"
    google_client.models.generate_content.assert_called_once()
    nvidia_client.chat.completions.create.assert_called_once()


def test_exhausted_provider_chain_does_not_retry_final_provider(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "google")
    monkeypatch.setenv("GOOGLE_API_KEY", "google-fake-key")
    monkeypatch.setenv("NVAPI_KEY", "nvapi-fallback")

    google_client = MagicMock()
    google_client.models.generate_content.side_effect = TimeoutError("google timeout")
    nvidia_client = MagicMock()
    nvidia_client.chat.completions.create.side_effect = TimeoutError("nvidia timeout")

    def configure_google(reasoner, _api_key):
        reasoner.client = google_client

    with patch.object(LLMReasoner, "_configure_google_client", configure_google), \
            patch("core.decision_engine.llm_reasoner.OpenAI", return_value=nvidia_client), \
            patch("core.decision_engine.llm_reasoner.time.sleep") as sleep:
        reasoner = LLMReasoner()
        result = reasoner._call_llm("hello")

    assert result == ""
    assert reasoner.runtime_summary()["failovers"] == 1
    google_client.models.generate_content.assert_called_once()
    nvidia_client.chat.completions.create.assert_called_once()
    sleep.assert_not_called()


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
    assert call_kwargs["max_tokens"] == 2000
    assert call_kwargs["messages"] == [{"role": "user", "content": "hello"}]
    assert result == "some response"
    assert reasoner.runtime_summary()["successful_calls"] == 1
    assert reasoner.runtime_summary()["last_successful_provider"] == "openai"


def test_shared_reasoner_serializes_concurrent_provider_calls():
    import threading
    from concurrent.futures import ThreadPoolExecutor

    mock_client = MagicMock()
    first_entered = threading.Event()
    second_started = threading.Event()
    release_first = threading.Event()
    call_count = 0
    count_lock = threading.Lock()

    def create(**_kwargs):
        nonlocal call_count
        with count_lock:
            call_count += 1
            current = call_count
        if current == 1:
            first_entered.set()
            assert release_first.wait(timeout=2)
        return MagicMock(choices=[MagicMock(message=MagicMock(content="ok"))])

    mock_client.chat.completions.create.side_effect = create
    reasoner = LLMReasoner(client=mock_client)

    def invoke(prompt):
        if prompt == "second":
            second_started.set()
        return reasoner._call_llm(prompt)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(invoke, "first")
        assert first_entered.wait(timeout=1)
        second = pool.submit(invoke, "second")
        assert second_started.wait(timeout=1)
        # The second worker reached the reasoner but cannot dispatch through
        # the shared mutable client until the first call releases the lock.
        assert call_count == 1
        release_first.set()
        assert first.result(timeout=2) == "ok"
        assert second.result(timeout=2) == "ok"

    assert call_count == 2
    assert reasoner.runtime_summary()["successful_calls"] == 2


def test_call_llm_falls_back_on_exception():
    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = Exception("API down")
    reasoner = LLMReasoner(client=mock_client)
    result = reasoner._call_llm("hello")
    assert result == ""
    assert reasoner.client is None
    assert reasoner.provider == "none"


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


def test_call_llm_uses_google_generate_content():
    mock_client = MagicMock()
    mock_client.models.generate_content.return_value = MagicMock(text="gemini response")
    reasoner = LLMReasoner(
        client=mock_client,
        model="gemini-test-model",
        provider="google",
    )
    result = reasoner._call_llm("hello")

    mock_client.models.generate_content.assert_called_once_with(
        model="gemini-test-model",
        contents="hello",
        config={"temperature": 0.0, "max_output_tokens": 2000},
    )
    assert result == "gemini response"


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


def test_call_llm_disables_client_on_authorization_error():
    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = Exception("403 Forbidden")
    reasoner = LLMReasoner(client=mock_client)

    first = reasoner._call_llm("hello")
    second = reasoner._call_llm("hello again")

    assert first == ""
    assert second == ""
    assert reasoner.client is None
    assert reasoner.provider == "none"
    mock_client.chat.completions.create.assert_called_once()


# ── heuristic fallback still works ───────────────────────────────────

def test_heuristic_fallback_when_no_client():
    reasoner = LLMReasoner(client=None)
    analysis = reasoner.analyze_challenge(SAMPLE_CHALLENGE)
    assert analysis.category_guess == "crypto"
    assert analysis.recommended_target == "crypto_agent"


def test_crypto_source_and_ciphertext_pair_routes_to_crypto_before_reverse():
    reasoner = LLMReasoner(client=None)
    challenge = {
        "id": "affine_bundle",
        "name": "Negotiation Message",
        "category": "crypto",
        "description": "Decrypt this confidential message.",
        "files": ["/tmp/chall.py", "/tmp/msg.enc"],
        "hints": [],
        "tags": [],
    }

    analysis = reasoner.analyze_challenge(challenge)

    assert analysis.category_guess == "crypto"
    assert analysis.recommended_target == "crypto_agent"


def test_live_web_challenge_bypasses_llm_initial_analysis(monkeypatch):
    mock_client = MagicMock()
    reasoner = LLMReasoner(client=mock_client)

    def fail_call(_prompt):
        raise AssertionError("live web fast path should not call the LLM")

    monkeypatch.setattr(reasoner, "_call_llm", fail_call)

    challenge = {
        "id": "clippygpt",
        "category": "web",
        "description": "ClippyGPT web challenge",
        "url": "https://example.web.ctf.local",
    }

    analysis = reasoner.analyze_challenge(challenge)
    decision = reasoner.choose_next_action(challenge, analysis, [])

    assert analysis.category_guess == "web"
    assert decision["next_action"] == "run_agent"
    assert decision["target"] == "web_agent"


def test_explicit_pwn_challenge_bypasses_llm_initial_analysis(monkeypatch):
    mock_client = MagicMock()
    reasoner = LLMReasoner(client=mock_client)

    def fail_call(_prompt):
        raise AssertionError("explicit pwn fast path should not call the LLM")

    monkeypatch.setattr(reasoner, "_call_llm", fail_call)

    challenge = {
        "id": "pwn_execute",
        "category": "pwn",
        "description": "Pwn challenge with source and remote host:port",
        "files": ["/tmp/execute", "/tmp/execute.c"],
    }

    analysis = reasoner.analyze_challenge(challenge)
    decision = reasoner.choose_next_action(challenge, analysis, [])

    assert analysis.category_guess == "pwn"
    assert decision["next_action"] == "run_agent"
    assert decision["target"] == "pwn_agent"


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


def test_sdk_timeout_is_retryable_not_fatal(monkeypatch):
    """Regression: a transient SDK APITimeoutError must be retried, and must
    NOT permanently disable the LLM client for the rest of the run.

    Previously `_RETRYABLE_EXCEPTIONS` only listed the builtin TimeoutError,
    so the SDK's APITimeoutError (subclass of APIConnectionError) fell through
    to the catch-all handler, was logged as "non-retryable", and called
    `_disable_llm()` — dropping the whole run into the heuristic fallback.
    """
    import anthropic
    from core.decision_engine.llm_reasoner import _RETRYABLE_EXCEPTIONS, _MAX_LLM_RETRIES

    # The SDK timeout type must be recognized as retryable.
    assert anthropic.APITimeoutError in _RETRYABLE_EXCEPTIONS

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    with patch("core.decision_engine.llm_reasoner.Anthropic") as MockAnthropic:
        client = MagicMock()
        client.messages.create.side_effect = anthropic.APITimeoutError(request=MagicMock())
        MockAnthropic.return_value = client
        reasoner = LLMReasoner()

    # Avoid real backoff sleeps.
    with patch("core.decision_engine.llm_reasoner.time.sleep"):
        result = reasoner._call_llm("hello")

    # Exhausting retries returns empty, but the client stays alive for later steps.
    assert result == ""
    assert client.messages.create.call_count == _MAX_LLM_RETRIES
    assert reasoner.client is not None
    assert reasoner.provider == "anthropic"

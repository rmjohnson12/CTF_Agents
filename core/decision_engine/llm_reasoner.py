from __future__ import annotations

import json
import logging
import os
import re
import time
import importlib
from dataclasses import asdict
from typing import Any, Dict, List, Optional


from openai import OpenAI
from anthropic import Anthropic
from dotenv import load_dotenv
from core.utils.security import redact_sensitive_data


def _collect_sdk_retryable_exceptions() -> tuple[type[BaseException], ...]:
    """SDK timeout/connection errors that should be retried, not treated as fatal.

    The OpenAI/Anthropic SDKs raise their own ``APITimeoutError`` /
    ``APIConnectionError`` (message: "Request timed out."), which do NOT
    subclass the builtin ``TimeoutError``. Without this, a single transient
    timeout falls through to the catch-all handler and disables the LLM for
    the entire run.
    """
    excs: list[type[BaseException]] = []
    for module_name in ("openai", "anthropic", "httpx"):
        try:
            mod = importlib.import_module(module_name)
        except Exception:
            continue
        for attr in ("APITimeoutError", "APIConnectionError", "TimeoutException", "NetworkError"):
            exc = getattr(mod, attr, None)
            if isinstance(exc, type) and issubclass(exc, BaseException):
                excs.append(exc)
    return tuple(excs)

# Load environment variables from .env file
load_dotenv()

from core.decision_engine.classifier import ChallengeAnalysis, ChallengeClassifier  # noqa: E402
from core.decision_engine.strategy_selector import StrategySelector  # noqa: E402

# Re-export so existing callers (tests, coordinator) keep working unchanged.
__all__ = ["LLMReasoner", "ChallengeAnalysis"]

logger = logging.getLogger(__name__)


_NVIDIA_NIM_BASE_URL = "https://integrate.api.nvidia.com/v1"
_OLLAMA_DEFAULT_BASE_URL = "http://localhost:11434/v1"
_NVIDIA_DEFAULT_MODEL = "meta/llama-3.3-70b-instruct"
_ANTHROPIC_DEFAULT_MODEL = "claude-sonnet-4-5-20250929"
_OLLAMA_DEFAULT_MODEL = "llama3.1"
_GOOGLE_DEFAULT_MODEL = "gemini-2.5-flash"

_RETRYABLE_EXCEPTIONS = (ConnectionError, TimeoutError) + _collect_sdk_retryable_exceptions()
_MAX_LLM_RETRIES = 3
_LLM_BACKOFF_BASE = 1.0
_DEFAULT_LLM_TIMEOUT_SECONDS = 20.0


class LLMReasoner:
    """
    Uses an LLM client for challenge analysis and action selection.

    Priority order for auto-configuration:
      1. Explicit client passed in
      2. LLM_PROVIDER env var preference: ollama|nvidia|anthropic|openai|google
      3. NVAPI_KEY/NGC_API_KEY env var → NVIDIA NIM (OpenAI-compatible)
      4. ANTHROPIC_API_KEY env var → Claude
      5. OPENAI_API_KEY env var → OpenAI
      6. GOOGLE_API_KEY/GEMINI_API_KEY or Google Cloud ADC → Gemini
      7. Heuristic fallback
    """

    def __init__(
        self,
        client: Optional[Any] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
    ):
        self.provider = (provider or os.getenv("LLM_PROVIDER") or "").strip().lower()
        self._nvidia_keys: List[str] = []
        self._nvidia_key_index = 0
        self._provider_candidates: List[str] = []
        self._provider_candidate_index = -1
        self._provider_model_override = model
        self._anthropic_key: Optional[str] = None
        self._openai_key: Optional[str] = None
        self._google_key: Optional[str] = None
        self._llm_calls = 0
        self._llm_successes = 0
        self._llm_failovers = 0
        self._last_successful_provider: Optional[str] = None
        self._last_successful_model: Optional[str] = None
        self.timeout_seconds = self._load_timeout_seconds()
        self._classifier = ChallengeClassifier()
        self._strategy_selector = StrategySelector()

        if client is not None:
            self.client = client
            self.provider = self.provider or "openai"
            self.model = model or "gpt-4o"
        else:
            self._nvidia_keys = self._load_nvidia_keys()
            anthropic_key = self._anthropic_key = os.getenv("ANTHROPIC_API_KEY")
            openai_key = self._openai_key = os.getenv("OPENAI_API_KEY")
            google_key = self._google_key = self._load_google_api_key()
            provider_order = self._provider_order(self.provider)
            self._provider_candidates = [
                candidate for candidate in provider_order
                if self._provider_is_configured(candidate)
            ]

            self.client = None
            self.model = model or "none"
            self.provider = "none"

            for candidate in self._provider_candidates:
                if candidate == "ollama":
                    self.provider = "ollama"
                    self._configure_ollama_client()
                    self.model = model or os.getenv("OLLAMA_MODEL") or _OLLAMA_DEFAULT_MODEL
                    break

                if candidate == "nvidia" and self._nvidia_keys:
                    self.provider = "nvidia"
                    self._configure_nvidia_client(0)
                    self.model = model or os.getenv("NVIDIA_MODEL") or _NVIDIA_DEFAULT_MODEL
                    break

                if candidate == "anthropic" and anthropic_key:
                    self.provider = "anthropic"
                    self.client = Anthropic(api_key=anthropic_key, timeout=self.timeout_seconds)
                    self.model = model or os.getenv("ANTHROPIC_MODEL") or _ANTHROPIC_DEFAULT_MODEL
                    break

                if candidate == "openai" and openai_key:
                    self.provider = "openai"
                    self.client = OpenAI(api_key=openai_key, timeout=self.timeout_seconds)
                    self.model = model or os.getenv("OPENAI_MODEL") or "gpt-4o"
                    break

                if candidate == "google" and self._google_config_available(google_key):
                    self.provider = "google"
                    self._configure_google_client(google_key)
                    self.model = model or os.getenv("GOOGLE_MODEL") or _GOOGLE_DEFAULT_MODEL
                    break
            if self.provider in self._provider_candidates:
                self._provider_candidate_index = self._provider_candidates.index(self.provider)

    @property
    def is_available(self) -> bool:
        """Checks if the LLM client is configured and available."""
        return self.client is not None

    @staticmethod
    def _load_nvidia_keys() -> List[str]:
        raw_keys = []
        for env_name in ("NVAPI_KEYS", "NVAPI_KEY", "NGC_API_KEY"):
            raw_keys.extend((os.getenv(env_name) or "").split(","))

        keys: List[str] = []
        for key in raw_keys:
            key = key.strip()
            if key and key not in keys:
                keys.append(key)
        return keys

    @staticmethod
    def _load_google_api_key() -> Optional[str]:
        for env_name in ("GOOGLE_API_KEY", "GEMINI_API_KEY"):
            key = (os.getenv(env_name) or "").strip()
            if key and not key.startswith("your_"):
                return key
        return None

    @staticmethod
    def _load_timeout_seconds() -> float:
        raw_timeout = os.getenv("LLM_TIMEOUT_SECONDS", "").strip()
        if not raw_timeout:
            return _DEFAULT_LLM_TIMEOUT_SECONDS
        try:
            return max(1.0, float(raw_timeout))
        except ValueError:
            logger.warning(
                "Invalid LLM_TIMEOUT_SECONDS=%r; using %.1fs.",
                raw_timeout,
                _DEFAULT_LLM_TIMEOUT_SECONDS,
            )
            return _DEFAULT_LLM_TIMEOUT_SECONDS

    def _configure_nvidia_client(self, key_index: int) -> None:
        self._nvidia_key_index = key_index
        self.client = OpenAI(
            api_key=self._nvidia_keys[key_index],
            base_url=_NVIDIA_NIM_BASE_URL,
            timeout=self.timeout_seconds,
        )

    def _configure_ollama_client(self) -> None:
        self.client = OpenAI(
            api_key=os.getenv("OLLAMA_API_KEY") or "ollama",
            base_url=os.getenv("OLLAMA_BASE_URL") or _OLLAMA_DEFAULT_BASE_URL,
            timeout=self.timeout_seconds,
        )

    @staticmethod
    def _google_config_available(api_key: Optional[str]) -> bool:
        if api_key:
            return True
        cloud_requested = (
            (os.getenv("GOOGLE_GENAI_USE_VERTEXAI") or "").strip().lower() in {"1", "true", "yes"}
            or (os.getenv("GOOGLE_GENAI_USE_ENTERPRISE") or "").strip().lower() in {"1", "true", "yes"}
        )
        return bool(
            cloud_requested
            and (os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GOOGLE_PROJECT_ID"))
        )

    def _configure_google_client(self, api_key: Optional[str]) -> None:
        genai = importlib.import_module("google.genai")
        project = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GOOGLE_PROJECT_ID")
        location = os.getenv("GOOGLE_CLOUD_LOCATION") or os.getenv("GOOGLE_LOCATION") or "global"
        cloud_requested = (
            (os.getenv("GOOGLE_GENAI_USE_VERTEXAI") or "").strip().lower() in {"1", "true", "yes"}
            or (os.getenv("GOOGLE_GENAI_USE_ENTERPRISE") or "").strip().lower() in {"1", "true", "yes"}
        )

        if cloud_requested and project and not api_key:
            self.client = genai.Client(
                vertexai=True,
                project=project,
                location=location,
                http_options={"timeout": int(self.timeout_seconds * 1000)},
            )
            return

        self.client = genai.Client(
            api_key=api_key,
            http_options={"timeout": int(self.timeout_seconds * 1000)},
        )

    def _rotate_nvidia_key(self) -> bool:
        if self.provider != "nvidia" or len(self._nvidia_keys) <= 1:
            return False

        next_index = self._nvidia_key_index + 1
        if next_index >= len(self._nvidia_keys):
            return False

        self._configure_nvidia_client(next_index)
        logger.warning(
            "NVIDIA LLM key failed with a temporary service/quota error; rotating to configured fallback key %d/%d.",
            next_index + 1,
            len(self._nvidia_keys),
        )
        return True

    def _provider_is_configured(self, provider: str) -> bool:
        return {
            "ollama": True,
            "nvidia": bool(self._nvidia_keys),
            "anthropic": bool(self._anthropic_key),
            "openai": bool(self._openai_key),
            "google": self._google_config_available(self._google_key),
        }.get(provider, False)

    def _advance_provider(self) -> bool:
        """Move to the next configured provider after quota/auth/service failure."""
        for index in range(self._provider_candidate_index + 1, len(self._provider_candidates)):
            candidate = self._provider_candidates[index]
            try:
                if candidate == "ollama":
                    self._configure_ollama_client()
                    selected_model = os.getenv("OLLAMA_MODEL") or _OLLAMA_DEFAULT_MODEL
                elif candidate == "nvidia":
                    self._configure_nvidia_client(0)
                    selected_model = os.getenv("NVIDIA_MODEL") or _NVIDIA_DEFAULT_MODEL
                elif candidate == "anthropic":
                    self.client = Anthropic(api_key=self._anthropic_key, timeout=self.timeout_seconds)
                    selected_model = os.getenv("ANTHROPIC_MODEL") or _ANTHROPIC_DEFAULT_MODEL
                elif candidate == "openai":
                    self.client = OpenAI(api_key=self._openai_key, timeout=self.timeout_seconds)
                    selected_model = os.getenv("OPENAI_MODEL") or "gpt-4o"
                elif candidate == "google":
                    self._configure_google_client(self._google_key)
                    selected_model = os.getenv("GOOGLE_MODEL") or _GOOGLE_DEFAULT_MODEL
                else:
                    continue
            except Exception as exc:
                logger.warning("Could not initialize fallback LLM provider %s: %s", candidate, exc)
                continue

            previous = self.provider
            self.provider = candidate
            self.model = self._provider_model_override or selected_model
            self._provider_candidate_index = index
            self._llm_failovers += 1
            logger.warning(
                "LLM provider %s failed; continuing this run with configured fallback %s.",
                previous,
                candidate,
            )
            return True
        return False

    def runtime_summary(self) -> Dict[str, Any]:
        """Return secret-free provider telemetry for reports and debugging."""
        return {
            "configured_providers": list(self._provider_candidates),
            "active_provider": self.provider,
            "active_model": self.model,
            "calls": self._llm_calls,
            "successful_calls": self._llm_successes,
            "failovers": self._llm_failovers,
            "last_successful_provider": self._last_successful_provider,
            "last_successful_model": self._last_successful_model,
        }

    def _record_llm_success(self, text: str) -> str:
        if text:
            self._llm_successes += 1
            self._last_successful_provider = self.provider
            self._last_successful_model = self.model
        return text

    @staticmethod
    def _provider_order(provider: str) -> List[str]:
        default_order = ["nvidia", "anthropic", "openai", "google"]
        aliases = {
            "nim": "nvidia",
            "claude": "anthropic",
            "gemini": "google",
            "vertex": "google",
            "vertexai": "google",
            "local": "ollama",
            "off": "none",
            "disabled": "none",
            "heuristic": "none",
        }
        provider = aliases.get(provider, provider)

        if provider == "none":
            return []

        if provider == "ollama":
            return ["ollama"] + default_order

        if provider in default_order:
            return [provider] + [p for p in default_order if p != provider]

        return default_order

    def analyze_challenge(self, challenge: Dict[str, Any]) -> ChallengeAnalysis:
        if self._direct_agent_for_category(challenge):
            return self._heuristic_analysis(challenge)

        if self.client is None:
            return self._heuristic_analysis(challenge)

        prompt = self._build_analysis_prompt(challenge)
        raw = self._call_llm(prompt)

        try:
            # Clean up possible markdown blocks
            raw = raw.strip().replace("```json", "").replace("```", "").strip()
            data = json.loads(raw)
            return ChallengeAnalysis(
                category_guess=data.get("category_guess", "unknown"),
                confidence=float(data.get("confidence", 0.0)),
                reasoning=data.get("reasoning", "No reasoning provided."),
                recommended_target=data.get("recommended_target", "none"),
                recommended_action=data.get("recommended_action", "stop"),
                detected_indicators=data.get("detected_indicators", []),
            )
        except Exception:
            return self._heuristic_analysis(challenge)

    def choose_next_action(
        self,
        challenge: Dict[str, Any],
        analysis: ChallengeAnalysis,
        history: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        direct_agent = self._direct_agent_for_category(challenge)
        if direct_agent and not history and self._analysis_allows_direct_route(direct_agent, analysis):
            return {
                "next_action": "run_agent",
                "target": direct_agent,
                "reasoning": (
                    f"Detected an already-classified {challenge.get('category')} challenge; "
                    f"dispatching directly to {direct_agent} before LLM recovery."
                ),
                "inputs": {},
            }

        if self._is_web_prime_product_runner(challenge):
            return {
                "next_action": "run_agent",
                "target": "web_agent",
                "reasoning": "Detected a web-hosted prime-product code-runner challenge.",
                "inputs": {},
            }

        if self._is_hardware_logic_challenge(challenge):
            return {
                "next_action": "run_agent",
                "target": "hardware_agent",
                "reasoning": "Detected a hardware logic challenge with schematic/table inputs.",
                "inputs": {},
            }

        # MASTER PIVOT: If we have a .py file and it's a crypto challenge, and we already tried crypto, pivot to coding
        files = challenge.get("files", [])
        has_script = any(f.endswith(".py") for f in files)
        if has_script and any(h.get("agent_id") == "crypto_agent" for h in history):
            return {
                "next_action": "run_agent",
                "target": "coding_agent",
                "reasoning": "Crypto agent could not solve it directly. MASTER PIVOT: Handing to coding agent to analyze the provided script.",
                "inputs": {"task": "Analyze the encryption script and implement a decryption routine for the output."}
            }

        if self.client is None:
            return self._heuristic_next_action(challenge, analysis, history)

        prompt = self._build_next_action_prompt(challenge, analysis, history)
        raw = self._call_llm(prompt)

        try:
            raw = raw.strip().replace("```json", "").replace("```", "").strip()
            return json.loads(raw)
        except Exception:
            return self._heuristic_next_action(challenge, analysis, history)

    def suggest_recovery_action(
        self,
        challenge: Dict[str, Any],
        analysis: ChallengeAnalysis,
        history: List[Dict[str, Any]],
        steps: List[str],
    ) -> Dict[str, Any]:
        """
        Ask the LLM for one concrete next step after the normal workflow stalls.

        This intentionally has no heuristic fallback: if no model is configured,
        the coordinator should preserve the existing deterministic behavior.
        """
        if self.client is None:
            return {
                "next_action": "stop",
                "target": "none",
                "reasoning": "LLM recovery review unavailable.",
                "inputs": {},
            }

        prompt = self._build_recovery_prompt(challenge, analysis, history, steps)
        raw = self._call_llm(prompt)

        try:
            raw = raw.strip().replace("```json", "").replace("```", "").strip()
            data = json.loads(raw)
        except Exception:
            return {
                "next_action": "stop",
                "target": "none",
                "reasoning": "LLM recovery review returned invalid JSON.",
                "inputs": {},
            }

        action = data.get("next_action", "stop")
        target = data.get("target", "none")
        if action not in {"run_agent", "run_tool", "stop"}:
            action = "stop"
        if action == "stop":
            target = "none"
        if target == "tony_htb_sql" and not self._has_sql_recovery_evidence(challenge, steps):
            action = "stop"
            target = "none"
            data["reasoning"] = (
                "Rejected SQL recovery suggestion because the trace did not contain "
                "SQL-specific evidence such as SQL errors, database terms, query parameters, "
                "or login/search forms."
            )

        return {
            "next_action": action,
            "target": target,
            "reasoning": data.get("reasoning", "No recovery reasoning provided."),
            "inputs": data.get("inputs") if isinstance(data.get("inputs"), dict) else {},
        }

    def synthesize_runtime_tool(
        self,
        challenge: Dict[str, Any],
        history: List[Dict[str, Any]],
        steps: List[str],
        allowed_operations: List[str],
    ) -> Optional[Dict[str, Any]]:
        """Propose one evidence-bound tool using the constrained runtime DSL."""
        if self.client is None:
            return None
        safe_challenge = redact_sensitive_data(challenge)
        safe_history = redact_sensitive_data(history[-6:])
        safe_steps = redact_sensitive_data(steps[-60:])
        prompt = f"""
You are the tool-building recovery stage for a stalled CTF workflow. Compose one
small, ephemeral tool from the allowed declarative operations. Do not emit
Python, shell commands, package installs, credentials, or prose outside JSON.

Allowed operations: {json.dumps(allowed_operations)}

Return exactly this shape:
{{
  "name": "short_tool_name",
  "hypothesis": "what new evidence this tests",
  "evidence": ["specific observed trace fact"],
  "operations": [
    {{"op": "http_request|read_artifact|regex_extract|decode|json_extract", "save_as": "variable", "other_fields": "as needed"}}
  ]
}}

Operation fields:
- http_request: url (same-origin absolute or relative), method GET/POST,
  optional data object, headers object, timeout_s.
- read_artifact: path must be one of the supplied artifacts or inside a supplied directory.
- regex_extract: source variable, pattern, optional integer group.
- decode: source variable, encoding base64/hex/url.
- json_extract: source variable, dot-separated path.
Every source variable must have been produced by an earlier operation. Use at
most 12 operations. Prefer a narrow experiment grounded in observed evidence.

Challenge:
{json.dumps(safe_challenge, indent=2, default=str)}

Recent trace:
{json.dumps(safe_steps, indent=2, default=str)}

Recent results:
{json.dumps(safe_history, indent=2, default=str)}
""".strip()
        try:
            raw = self._call_llm(prompt)
            cleaned = raw.strip().replace("```json", "").replace("```", "").strip()
            proposal = json.loads(cleaned)
            return proposal if isinstance(proposal, dict) else None
        except Exception as exc:
            logger.warning("Runtime tool synthesis proposal failed: %s", exc)
            return None

    @staticmethod
    def _has_sql_recovery_evidence(challenge: Dict[str, Any], steps: List[str]) -> bool:
        text = " ".join([
            str(challenge.get("name", "")),
            str(challenge.get("description", "")),
            " ".join(challenge.get("tags", [])),
            " ".join(str(step) for step in steps[-50:]),
        ]).lower()
        sql_markers = [
            "sql",
            "sqlite",
            "mysql",
            "postgres",
            "database",
            "dbms",
            "union select",
            "syntax error",
            "login",
            "search",
            "query parameter",
            "id=",
        ]
        artifact_markers = [
            "x-archived-path",
            "header artifact",
            "certutil",
            "backup",
            "binary stl",
            "openscad",
            "svg text",
        ]
        return any(marker in text for marker in sql_markers) and not (
            any(marker in text for marker in artifact_markers)
            and not any(marker in text for marker in ["sql", "sqlite", "mysql", "postgres", "dbms", "union select"])
        )

    def _call_llm(self, prompt: str) -> str:
        if not self.client:
            return ""

        max_attempts = _MAX_LLM_RETRIES * max(1, len(self._provider_candidates)) + len(self._nvidia_keys)
        retry_count = 0
        for attempt in range(1, max_attempts + 1):
            self._llm_calls += 1
            try:
                if self.provider == "anthropic":
                    response = self.client.messages.create(
                        model=self.model,
                        max_tokens=2000,
                        messages=[{"role": "user", "content": prompt}],
                    )
                    return self._record_llm_success(self._extract_anthropic_text(response))
                if self.provider == "google":
                    response = self.client.models.generate_content(
                        model=self.model,
                        contents=prompt,
                    )
                    return self._record_llm_success(self._extract_google_text(response))
                else:
                    response = self.client.chat.completions.create(
                        model=self.model,
                        messages=[{"role": "user", "content": prompt}],
                    )
                    return self._record_llm_success(response.choices[0].message.content or "")
            except _RETRYABLE_EXCEPTIONS as exc:
                retry_count += 1
                if self._advance_provider():
                    retry_count = 0
                    continue
                if retry_count >= _MAX_LLM_RETRIES:
                    logger.error(
                        "LLM call exhausted all %d retries after retryable error: %s",
                        _MAX_LLM_RETRIES,
                        exc,
                    )
                    break
                if self._llm_failovers:
                    logger.error(
                        "All configured LLM providers failed during this call; "
                        "returning to deterministic recovery without retrying the final provider."
                    )
                    break
                wait = _LLM_BACKOFF_BASE * (2 ** (retry_count - 1))
                logger.warning(
                    "LLM call failed (%s), retrying in %.1fs (attempt %d/%d)",
                    exc, wait, attempt, _MAX_LLM_RETRIES,
                )
                time.sleep(wait)
            except Exception as exc:
                if "503" in str(exc) or "429" in str(exc):
                    if self._rotate_nvidia_key():
                        continue
                    if self._advance_provider():
                        retry_count = 0
                        continue
                    logger.error("LLM service temporarily unavailable (503/429). Fast-failing to heuristic mode.")
                    self._disable_llm()
                    return ""
                if "403" in str(exc) or "401" in str(exc) or "Unauthorized" in str(exc) or "Forbidden" in str(exc):
                    if self._advance_provider():
                        retry_count = 0
                        continue
                    logger.error("LLM authorization failed. Disabling LLM for this run and falling back to heuristic mode.")
                    self._disable_llm()
                    return ""
                logger.error("LLM call failed with non-retryable error: %s", exc)
                self._disable_llm()
                return ""

        return ""

    def _disable_llm(self) -> None:
        self.client = None
        self.provider = "none"
        self.model = "none"

    @staticmethod
    def _extract_anthropic_text(response: Any) -> str:
        """Extract plain text from Anthropic Messages API responses."""
        blocks = getattr(response, "content", [])
        parts: List[str] = []

        for block in blocks:
            if isinstance(block, str):
                parts.append(block)
                continue
            if isinstance(block, dict):
                text = block.get("text")
            else:
                text = getattr(block, "text", None)
            if text:
                parts.append(text)

        return "".join(parts)

    @staticmethod
    def _extract_google_text(response: Any) -> str:
        text = getattr(response, "text", None)
        if text:
            return text

        parts: List[str] = []
        for candidate in getattr(response, "candidates", []) or []:
            content = getattr(candidate, "content", None)
            for part in getattr(content, "parts", []) or []:
                part_text = getattr(part, "text", None)
                if part_text:
                    parts.append(part_text)
        return "".join(parts)

    def generate_script(self, challenge: Dict[str, Any], task_desc: str) -> str:
        """Use LLM to generate a Python script for a specific task."""
        prompt = f"""
        You are a World-Class CTF Exploitation Expert.
        Write a Python script to solve the following task:
        Task: {task_desc}
        
        Challenge Context:
        {json.dumps(challenge, indent=2)}
        
        CRITICAL RULES for CTF Logic:
        1. DATA DECODING: If you read from a file, check if it's hex (0-9, a-f) or Base64. Decode it to raw bytes before processing. Strip labels like 'Flag: ' or 'Cipher: '.
        2. XOR STRATEGY: If multi-byte XOR is suspected, use a 'Known Plaintext Attack'. Try deriving the key by XORing the first bytes of ciphertext with common prefixes: 'SVIUSCG{{', 'SVIBGR{{', 'SVBRG{{', 'picoCTF{{', 'HTB{{', 'CTF{{', 'flag{{', 'SKY-'.
        3. OUTPUT: Print the final flag clearly (e.g. 'Found flag: SVIBGR{{...}}'). Flags may use the US Cyber Games formats SVIUSCG{{...}}, SVIBGR{{...}}, or SVBRG{{...}}.
        4. SELF-CONTAINED: Use only standard libraries (sys, os, binascii, base64, re, etc.).
        
        Return ONLY the Python code. No preamble, no markdown.
        """
        return self._call_llm(prompt).strip().replace("```python", "").replace("```", "").strip()

    def fix_script(self, challenge: Dict[str, Any], script: str, error: str, stdout: str) -> str:
        """Use LLM to fix a failing Python script based on its output."""
        prompt = f"""
        Fix the following Python script which failed during execution.
        
        Original Script:
        {script}
        
        Execution Error:
        {error}
        
        Execution Output:
        {stdout}
        
        Challenge Context:
        {json.dumps(challenge, indent=2)}
        
        Return ONLY the fixed Python code. No preamble, no markdown blocks.
        """
        return self._call_llm(prompt).strip().replace("```python", "").replace("```", "").strip()

    def _build_analysis_prompt(self, challenge: Dict[str, Any]) -> str:
        system_tools = challenge.get("metadata", {}).get("system_tools", [])
        tools_ctx = f"Available system tools: {', '.join(system_tools)}" if system_tools else ""

        # Include prior knowledge if present
        prior_knowledge = challenge.get("prior_knowledge", [])
        knowledge_ctx = f"\nPrior Knowledge (discovered facts):\n{json.dumps(prior_knowledge, indent=2)}" if prior_knowledge else ""

        return f"""
    You are analyzing a CTF challenge for routing and planning.
    {tools_ctx}
    {knowledge_ctx}

    Return ONLY valid JSON with this shape:
    {{
    "category_guess": "crypto|web|reverse|pwn|forensics|osint|log|misc|blockchain|secure_coding|unknown",
    "confidence": 0.0,
    "reasoning": "short explanation",
    "recommended_target": "pwn_agent|docker_agent|recon_agent|web_agent|crypto_agent|coding_agent|forensics_agent|reverse_agent|osint_agent|log_agent|networking_agent|blockchain_agent|secure_coding_agent|browser_snapshot|tony_htb_sql|none",
    "recommended_action": "run_agent|run_tool|stop",
    "detected_indicators": ["indicator1", "indicator2"]
    }}

    Use "pwn_agent" for binary exploitation challenges (buffer overflow, ROP, shellcode,
    heap exploits, format string bugs, ELF binaries with exploitation intent).
    Use "blockchain_agent" for blockchain, Ethereum, Solidity smart contract, and RPC-based challenges.
    Use "secure_coding_agent" for source-remediation challenges where the task is
    to patch vulnerable code through an editor/API and verify the fix.
    If the challenge references a local Docker/Dockerfile/container challenge folder,
    prefer recommended_target "docker_agent" with recommended_action "run_agent"
    before web exploitation. The docker_agent will publish a localhost URL for
    downstream web/recon agents.

    Challenge:
    {json.dumps(challenge, indent=2)}
    """.strip()

    def _build_next_action_prompt(
        self,
        challenge: Dict[str, Any],
        analysis: ChallengeAnalysis,
        history: List[Dict[str, Any]],
    ) -> str:
        system_tools = challenge.get("metadata", {}).get("system_tools", [])
        tools_ctx = f"Available system tools: {', '.join(system_tools)}" if system_tools else ""

        # Include prior knowledge if present
        prior_knowledge = challenge.get("prior_knowledge", [])
        knowledge_ctx = f"\nPrior Knowledge (discovered facts):\n{json.dumps(prior_knowledge, indent=2)}" if prior_knowledge else ""

        return f"""
    You are deciding the next step in a CTF agent workflow.
    {tools_ctx}
    {knowledge_ctx}

    Return ONLY valid JSON with this shape:
    {{
    "next_action": "run_agent|run_tool|stop",
    "target": "pwn_agent|docker_agent|recon_agent|web_agent|crypto_agent|coding_agent|forensics_agent|reverse_agent|osint_agent|log_agent|networking_agent|blockchain_agent|secure_coding_agent|browser_snapshot|tony_htb_sql|none",
    "reasoning": "short explanation",
    "inputs": {{}}
    }}

    Use "run_agent" for targets ending in "_agent".
    Use "run_tool" only for browser_snapshot or tony_htb_sql.
    If prior history shows docker_agent produced docker_target_url, run web_agent next.
    If the challenge is a secure-coding/source-remediation task, run secure_coding_agent.
    If the challenge references a local Docker/Dockerfile/container folder and no
    docker_target_url exists yet, run docker_agent first.

    Challenge:
    {json.dumps(challenge, indent=2)}

    Analysis:
    {json.dumps(asdict(analysis), indent=2)}

    History:
    {json.dumps(history, indent=2)}
    """.strip()

    def _build_recovery_prompt(
        self,
        challenge: Dict[str, Any],
        analysis: ChallengeAnalysis,
        history: List[Dict[str, Any]],
        steps: List[str],
    ) -> str:
        compact_history = history[-6:]
        recent_steps = steps[-40:]

        return f"""
    You are reviewing a stalled CTF agent workflow. The normal planner failed
    to recover a flag. Suggest exactly one concrete next action that is likely
    to produce new evidence.

    Return ONLY valid JSON with this shape:
    {{
    "next_action": "run_agent|run_tool|stop",
    "target": "pwn_agent|docker_agent|recon_agent|web_agent|crypto_agent|coding_agent|forensics_agent|reverse_agent|osint_agent|log_agent|networking_agent|blockchain_agent|secure_coding_agent|browser_snapshot|tony_htb_sql|none",
    "reasoning": "short explanation of why this action is different from prior failed attempts",
    "inputs": {{"task": "optional focused instruction for the selected agent"}}
    }}

    Rules:
    - Prefer an action that is different from prior failed attempts.
    - If retrying the same agent, include a focused inputs.task explaining the
      new hypothesis or specific tool/path to try.
    - Ground the action in observed evidence from the trace. If the trace
      mentions response headers, backup paths, certutil/PEM blocks, STL,
      OpenSCAD, zip/Krita, static JavaScript, source comments, or downloaded
      artifacts, prefer an artifact/file-analysis step over SQL scanning.
    - Do not suggest tony_htb_sql unless the trace shows SQL-specific evidence
      such as SQL errors, database names, query parameters, search/login forms,
      or prior SQL injection signals.
    - Use "run_agent" for targets ending in "_agent".
    - Use "run_tool" only for browser_snapshot or tony_htb_sql.
    - Use "stop" only if there is no concrete next experiment.

    Challenge:
    {json.dumps(challenge, indent=2)}

    Initial analysis:
    {json.dumps(asdict(analysis), indent=2)}

    Recent trace:
    {json.dumps(recent_steps, indent=2)}

    Recent results:
    {json.dumps(compact_history, indent=2)}
    """.strip()

    def _heuristic_analysis(self, challenge: Dict[str, Any]) -> ChallengeAnalysis:
        return self._classifier.classify(challenge)

    def _heuristic_next_action(
        self,
        challenge: Dict[str, Any],
        analysis: ChallengeAnalysis,
        history: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        return self._strategy_selector.select_next(challenge, analysis, history)

    @staticmethod
    def _is_web_prime_product_runner(challenge: Dict[str, Any]) -> bool:
        text = " ".join([
            str(challenge.get("name", "")),
            str(challenge.get("description", "")),
            " ".join(challenge.get("hints", [])),
            " ".join(challenge.get("tags", [])),
        ]).lower()
        has_url = bool(challenge.get("url") or challenge.get("target", {}).get("url"))
        return (
            has_url
            and "prime" in text
            and any(word in text for word in ["product", "multiply", "multiplying"])
            and any(word in text for word in ["number", "numbers", "list", "key"])
        )

    @staticmethod
    def _is_live_web_challenge(challenge: Dict[str, Any]) -> bool:
        if challenge.get("category") != "web":
            return False
        url = challenge.get("url") or challenge.get("target", {}).get("url")
        return bool(url)

    @staticmethod
    def _direct_agent_for_category(challenge: Dict[str, Any]) -> Optional[str]:
        category = str(challenge.get("category") or "").lower()
        direct_routes = {
            "web": "web_agent",
            "crypto": "crypto_agent",
            "cryptography": "crypto_agent",
            "reverse": "reverse_agent",
            "reversing": "reverse_agent",
            "rev": "reverse_agent",
            "forensics": "forensics_agent",
            "pwn": "pwn_agent",
            "binary": "pwn_agent",
            "hardware": "hardware_agent",
            "blockchain": "blockchain_agent",
            "secure_coding": "secure_coding_agent",
            "secure-coding": "secure_coding_agent",
            "log": "log_agent",
            "networking": "networking_agent",
            "network": "networking_agent",
            "osint": "osint_agent",
            "coding": "coding_agent",
        }
        return direct_routes.get(category)

    @staticmethod
    def _analysis_allows_direct_route(direct_agent: str, analysis: ChallengeAnalysis) -> bool:
        recommended = (analysis.recommended_target or "none").strip()
        return recommended in {"", "none", direct_agent}

    @staticmethod
    def _is_hardware_logic_challenge(challenge: Dict[str, Any]) -> bool:
        text = " ".join([
            str(challenge.get("name", "")),
            str(challenge.get("description", "")),
            " ".join(challenge.get("hints", [])),
            " ".join(challenge.get("tags", [])),
        ]).lower()
        files = [str(f).lower() for f in challenge.get("files", [])]
        has_csv = any(f.endswith(".csv") for f in files)
        has_image = any(f.endswith((".jpg", ".jpeg", ".png")) for f in files)
        return (
            challenge.get("category") == "hardware"
            or (has_csv and has_image)
            or any(
                re.search(r"\b" + re.escape(word) + r"\b", text)
                for word in ["hardware", "chip", "logic", "circuit", "gate"]
            )
        )

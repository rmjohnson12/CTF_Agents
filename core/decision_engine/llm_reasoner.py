from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict
from typing import Any, Dict, List, Optional


from openai import OpenAI
from anthropic import Anthropic
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from core.decision_engine.classifier import ChallengeAnalysis, ChallengeClassifier  # noqa: E402
from core.decision_engine.strategy_selector import StrategySelector  # noqa: E402

# Re-export so existing callers (tests, coordinator) keep working unchanged.
__all__ = ["LLMReasoner", "ChallengeAnalysis"]

logger = logging.getLogger(__name__)


_NVIDIA_NIM_BASE_URL = "https://integrate.api.nvidia.com/v1"
_NVIDIA_DEFAULT_MODEL = "meta/llama-3.3-70b-instruct"
_ANTHROPIC_DEFAULT_MODEL = "claude-sonnet-4-5-20250929"

_RETRYABLE_EXCEPTIONS = (ConnectionError, TimeoutError)
_MAX_LLM_RETRIES = 3
_LLM_BACKOFF_BASE = 1.0
_DEFAULT_LLM_TIMEOUT_SECONDS = 15.0


class LLMReasoner:
    """
    Uses an LLM client for challenge analysis and action selection.

    Priority order for auto-configuration:
      1. Explicit client passed in
      2. LLM_PROVIDER env var preference: nvidia|anthropic|openai
      3. NVAPI_KEY/NGC_API_KEY env var → NVIDIA NIM (OpenAI-compatible)
      4. ANTHROPIC_API_KEY env var → Claude
      5. OPENAI_API_KEY env var → OpenAI
      6. Heuristic fallback
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
        self.timeout_seconds = self._load_timeout_seconds()
        self._classifier = ChallengeClassifier()
        self._strategy_selector = StrategySelector()

        if client is not None:
            self.client = client
            self.provider = self.provider or "openai"
            self.model = model or "gpt-4o"
        else:
            self._nvidia_keys = self._load_nvidia_keys()
            anthropic_key = os.getenv("ANTHROPIC_API_KEY")
            openai_key = os.getenv("OPENAI_API_KEY")
            provider_order = self._provider_order(self.provider)

            self.client = None
            self.model = model or "none"
            self.provider = "none"

            for candidate in provider_order:
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

    @staticmethod
    def _provider_order(provider: str) -> List[str]:
        default_order = ["nvidia", "anthropic", "openai"]
        aliases = {
            "nim": "nvidia",
            "claude": "anthropic",
            "off": "none",
            "disabled": "none",
            "heuristic": "none",
        }
        provider = aliases.get(provider, provider)

        if provider == "none":
            return []

        if provider in default_order:
            return [provider] + [p for p in default_order if p != provider]

        return default_order

    def analyze_challenge(self, challenge: Dict[str, Any]) -> ChallengeAnalysis:
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

    def _call_llm(self, prompt: str) -> str:
        if not self.client:
            return ""

        max_attempts = max(_MAX_LLM_RETRIES, len(self._nvidia_keys) or 1)
        for attempt in range(1, max_attempts + 1):
            try:
                if self.provider == "anthropic":
                    response = self.client.messages.create(
                        model=self.model,
                        max_tokens=2000,
                        messages=[{"role": "user", "content": prompt}],
                    )
                    return self._extract_anthropic_text(response)
                else:
                    response = self.client.chat.completions.create(
                        model=self.model,
                        messages=[{"role": "user", "content": prompt}],
                    )
                    return response.choices[0].message.content or ""
            except _RETRYABLE_EXCEPTIONS as exc:
                if attempt == _MAX_LLM_RETRIES:
                    logger.error(
                        "LLM call exhausted all %d retries after retryable error: %s",
                        _MAX_LLM_RETRIES,
                        exc,
                    )
                    break
                wait = _LLM_BACKOFF_BASE * (2 ** (attempt - 1))
                logger.warning(
                    "LLM call failed (%s), retrying in %.1fs (attempt %d/%d)",
                    exc, wait, attempt, _MAX_LLM_RETRIES,
                )
                time.sleep(wait)
            except Exception as exc:
                if "503" in str(exc) or "429" in str(exc):
                    if self._rotate_nvidia_key():
                        continue
                    logger.error("LLM service temporarily unavailable (503/429). Fast-failing to heuristic mode.")
                    self._disable_llm()
                    return ""
                if "403" in str(exc) or "401" in str(exc) or "Unauthorized" in str(exc) or "Forbidden" in str(exc):
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
        2. XOR STRATEGY: If multi-byte XOR is suspected, use a 'Known Plaintext Attack'. Try deriving the key by XORing the first bytes of ciphertext with common prefixes: 'HTB{{', 'CTF{{', 'flag{{', 'SKY-'.
        3. OUTPUT: Print the final flag clearly (e.g. 'Found flag: HTB{{...}}').
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
    "category_guess": "crypto|web|reverse|pwn|forensics|osint|log|misc|unknown",
    "confidence": 0.0,
    "reasoning": "short explanation",
    "recommended_target": "pwn_agent|docker_agent|recon_agent|web_agent|crypto_agent|coding_agent|forensics_agent|reverse_agent|osint_agent|log_agent|networking_agent|browser_snapshot|tony_htb_sql|none",
    "recommended_action": "run_agent|run_tool|stop",
    "detected_indicators": ["indicator1", "indicator2"]
    }}

    Use "pwn_agent" for binary exploitation challenges (buffer overflow, ROP, shellcode,
    heap exploits, format string bugs, ELF binaries with exploitation intent).
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
    "target": "pwn_agent|docker_agent|recon_agent|web_agent|crypto_agent|coding_agent|forensics_agent|reverse_agent|osint_agent|log_agent|networking_agent|browser_snapshot|tony_htb_sql|none",
    "reasoning": "short explanation",
    "inputs": {{}}
    }}

    Use "run_agent" for targets ending in "_agent".
    Use "run_tool" only for browser_snapshot or tony_htb_sql.
    If prior history shows docker_agent produced docker_target_url, run web_agent next.
    If the challenge references a local Docker/Dockerfile/container folder and no
    docker_target_url exists yet, run docker_agent first.

    Challenge:
    {json.dumps(challenge, indent=2)}

    Analysis:
    {json.dumps(asdict(analysis), indent=2)}

    History:
    {json.dumps(history, indent=2)}
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

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

from openai import OpenAI
from anthropic import Anthropic
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger(__name__)


@dataclass
class ChallengeAnalysis:
    category_guess: str
    confidence: float
    reasoning: str
    recommended_target: str
    recommended_action: str
    detected_indicators: List[str]


_NVIDIA_NIM_BASE_URL = "https://integrate.api.nvidia.com/v1"
_NVIDIA_DEFAULT_MODEL = "meta/llama-3.3-70b-instruct"
_ANTHROPIC_DEFAULT_MODEL = "claude-sonnet-4-5-20250929"

_RETRYABLE_EXCEPTIONS = (ConnectionError, TimeoutError)
_MAX_LLM_RETRIES = 3
_LLM_BACKOFF_BASE = 1.0


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
                    self.client = Anthropic(api_key=anthropic_key)
                    self.model = model or os.getenv("ANTHROPIC_MODEL") or _ANTHROPIC_DEFAULT_MODEL
                    break

                if candidate == "openai" and openai_key:
                    self.provider = "openai"
                    self.client = OpenAI(api_key=openai_key)
                    self.model = model or os.getenv("OPENAI_MODEL") or "gpt-4o"
                    break

    @property
    def is_available(self) -> bool:
        """Checks if the LLM client is configured and available."""
        return self.client is not None

    @staticmethod
    def _load_nvidia_keys() -> List[str]:
        raw_keys = []
        raw_keys.extend((os.getenv("NVAPI_KEYS") or "").split(","))
        raw_keys.append(os.getenv("NVAPI_KEY") or "")
        raw_keys.append(os.getenv("NGC_API_KEY") or "")

        keys: List[str] = []
        for key in raw_keys:
            key = key.strip()
            if key and key not in keys:
                keys.append(key)
        return keys

    def _configure_nvidia_client(self, key_index: int) -> None:
        self._nvidia_key_index = key_index
        self.client = OpenAI(
            api_key=self._nvidia_keys[key_index],
            base_url=_NVIDIA_NIM_BASE_URL,
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
        }
        provider = aliases.get(provider, provider)

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
                    return ""
                logger.error("LLM call failed with non-retryable error: %s", exc)
                return ""

        return ""

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
    "recommended_target": "docker_agent|recon_agent|web_agent|crypto_agent|coding_agent|forensics_agent|reverse_agent|osint_agent|log_agent|networking_agent|browser_snapshot|tony_htb_sql|none",
    "recommended_action": "run_agent|run_tool|stop",
    "detected_indicators": ["indicator1", "indicator2"]
    }}

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
    "target": "docker_agent|recon_agent|web_agent|crypto_agent|coding_agent|forensics_agent|reverse_agent|osint_agent|log_agent|networking_agent|browser_snapshot|tony_htb_sql|none",
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

    @staticmethod
    def _kw(text: str, *words: str) -> bool:
        """True if any word/phrase matches as a whole word in text."""
        return any(re.search(r'\b' + re.escape(w) + r'\b', text) for w in words)

    def _heuristic_analysis(self, challenge: Dict[str, Any]) -> ChallengeAnalysis:
        # Only look at user-provided text for heuristics, ignore metadata (which contains tool names)
        text = " ".join([
            challenge.get("name", ""),
            challenge.get("description", ""),
            " ".join(challenge.get("hints", [])),
            " ".join(challenge.get("tags", [])),
        ]).lower()

        indicators: List[str] = []
        files = challenge.get("files", [])

        wants_docker_run = self._kw(
            text,
            "docker",
            "dockerfile",
            "container",
            "spawn",
            "run locally",
            "launch",
        )
        if self._has_docker_context(files) and wants_docker_run:
            indicators.append("docker_context")
            return ChallengeAnalysis(
                category_guess="web",
                confidence=0.91,
                reasoning="Detected a local Docker challenge context.",
                recommended_target="docker_agent",
                recommended_action="run_agent",
                detected_indicators=indicators,
            )

        # Priority 0: Network Forensics (PCAP)
        if any(f.endswith('.pcap') or f.endswith('.pcapng') for f in files) or self._kw(text, "pcap"):
            indicators.append("network_forensics")
            return ChallengeAnalysis(
                category_guess="forensics",
                confidence=0.96,
                reasoning="Detected PCAP files or network forensics keywords.",
                recommended_target="forensics_agent",
                recommended_action="run_agent",
                detected_indicators=indicators,
            )

        # Priority 1: Forensics-style binary artifacts.
        # A .bin can be a reverse task, but prompts asking for hidden/extracted data
        # should get strings/binwalk style analysis first.
        if (
            any(f.endswith('.bin') or f.endswith('.dat') for f in files)
            and self._kw(text, "hidden", "artifact", "extract", "embedded", "strings", "forensics")
        ):
            indicators.append("binary_artifact_forensics")
            return ChallengeAnalysis(
                category_guess="forensics",
                confidence=0.95,
                reasoning="Detected binary artifact with hidden/extraction-oriented wording.",
                recommended_target="forensics_agent",
                recommended_action="run_agent",
                detected_indicators=indicators,
            )

        # Priority 2: Reverse Engineering (Source/Binary analysis)
        if any(f.endswith('.py') or f.endswith('.exe') or f.endswith('.bin') or f.endswith('.elf') for f in files) or \
           self._kw(text, "reverse", "source code", "analyze program", "authenticate the program"):
            indicators.append("reverse_terms")
            return ChallengeAnalysis(
                category_guess="reverse",
                confidence=0.95,
                reasoning="Detected reverse engineering indicators or executable files.",
                recommended_target="reverse_agent",
                recommended_action="run_agent",
                detected_indicators=indicators,
            )

        # Priority 3: Forensics (if files are present or forensics keywords found)
        if any(f.endswith('.pdf') or f.endswith('.pcap') or f.endswith('.dat') for f in files) or \
           self._kw(text, "artifact", "extract", "binwalk", "forensics", "metadata", "exiftool"):
            indicators.append("forensics_terms")
            return ChallengeAnalysis(
                category_guess="forensics",
                confidence=0.94,
                reasoning="Detected forensic indicators or provided files.",
                recommended_target="forensics_agent",
                recommended_action="run_agent",
                detected_indicators=indicators,
            )

        # Priority 4: Log Analysis
        if (
            challenge.get("category") == "log"
            or any(f.endswith('.log') for f in files)
            or self._kw(text, "access log", "auth log", "server log", "brute force", "failed password", "ssh")
        ):
            indicators.append("log_terms")
            return ChallengeAnalysis(
                category_guess="log",
                confidence=0.86,
                reasoning="Detected log analysis indicators.",
                recommended_target="log_agent",
                recommended_action="run_agent",
                detected_indicators=indicators,
            )

        # Priority 5: Crypto / Decoding
        # Special check for numerical strings (decimal/octal encoding)
        if re.search(r'\b(?:\d{1,3}[\s,]+){3,}', text) or \
           self._kw(text, "cipher", "decrypt", "decode", "base64", "hex", "xor", "caesar", "password", "rockyou", "crack"):
            indicators.append("crypto_terms")
            return ChallengeAnalysis(
                category_guess="crypto",
                confidence=0.93,
                reasoning="Detected crypto/decoding indicators or numerical encoding.",
                recommended_target="crypto_agent",
                recommended_action="run_agent",
                detected_indicators=indicators,
            )

        # Priority 6: SQLi
        if self._kw(text, "sqli", "sql injection", "login bypass", "union select"):
            indicators.append("sqli_terms")
            return ChallengeAnalysis(
                category_guess="web",
                confidence=0.91,
                reasoning="Detected SQL injection indicators. Recommending tony_htb_sql tool.",
                recommended_target="tony_htb_sql",
                recommended_action="run_tool",
                detected_indicators=indicators,
            )

        # Priority 7: Web
        url = challenge.get("url")
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b'
        if url or re.search(ip_pattern, text) or self._kw(text, "url", "http", "login", "form", "page", "cookie", "endpoint", "jwt", "token", "session"):
            indicators.append("web_terms")

            if self._kw(text, "recon", "enumerate", "enumeration", "scan", "fingerprint", "discover"):
                indicators.append("recon_terms")
                return ChallengeAnalysis(
                    category_guess="web",
                    confidence=0.90,
                    reasoning="Detected explicit reconnaissance/enumeration request for a web or network target.",
                    recommended_target="recon_agent",
                    recommended_action="run_agent",
                    detected_indicators=indicators,
                )

            # Heuristic pivot: If "inspect", "form", "page", "source", "javascript", or "code" are used
            # prefer browser_snapshot tool for initial reconnaissance.
            if self._kw(text, "inspect", "form", "page", "snapshot", "look at", "source", "javascript", "js", "code", "analyze"):
                return ChallengeAnalysis(
                    category_guess="web",
                    confidence=0.89,
                    reasoning="Web challenge requiring initial inspection. Recommending browser_snapshot.",
                    recommended_target="browser_snapshot",
                    recommended_action="run_tool",
                    detected_indicators=indicators,
                )

            return ChallengeAnalysis(
                category_guess="web",
                confidence=0.88,
                reasoning="Detected web-related terms or URL.",
                recommended_target="web_agent",
                recommended_action="run_agent",
                detected_indicators=indicators,
            )

        # OSINT (Lower priority)
        if self._kw(text, "osint", "whois", "social media", "located"):
            indicators.append("osint_terms")
            return ChallengeAnalysis(
                category_guess="osint",
                confidence=0.85,
                reasoning="Detected OSINT indicators.",
                recommended_target="osint_agent",
                recommended_action="run_agent",
                detected_indicators=indicators,
            )

        # Priority 8: Coding
        if (
            challenge.get("category") == "misc"
            and self._kw(text, "calculate", "sum", "prime", "math", "format", "ctf")
        ) or self._kw(text, "script", "python", "automate", "program", "code", "algorithm"):
            indicators.append("coding_terms")
            return ChallengeAnalysis(
                category_guess="misc",
                confidence=0.80,
                reasoning="Detected programming or scripting indicators.",
                recommended_target="coding_agent",
                recommended_action="run_agent",
                detected_indicators=indicators,
            )

        return ChallengeAnalysis(
            category_guess=challenge.get("category", "unknown"),
            confidence=0.50,
            reasoning="No strong indicators found.",
            recommended_target="none",
            recommended_action="stop",
            detected_indicators=indicators,
        )

    def _heuristic_next_action(
        self,
        challenge: Dict[str, Any],
        analysis: ChallengeAnalysis,
        history: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        # Decision Quality: Check history for artifacts to pivot strategy
        last_result = history[-1] if history else {}
        last_agent = last_result.get("agent_id")
        last_status = last_result.get("status")
        last_artifacts = last_result.get("artifacts", {})

        if last_agent == "docker_agent" and last_artifacts.get("docker_target_url"):
            return {
                "next_action": "run_agent",
                "target": "web_agent",
                "reasoning": "Docker challenge is running locally. Handing mapped localhost URL to web_agent.",
                "inputs": {"url": last_artifacts["docker_target_url"]},
            }

        # Pivot: If any step found a login form, let coding_agent try to bypass it
        # Heuristic 1: If we have a .py file and it's a crypto challenge, and we already tried crypto, pivot to coding
        files = challenge.get("files", [])
        has_script = any(f.endswith(".py") for f in files)
        if has_script and any(h.get("agent_id") == "crypto_agent" for h in history):
            return {
                "next_action": "run_agent",
                "target": "coding_agent",
                "reasoning": "Crypto agent could not solve it directly. Pivoting to coding agent to analyze the provided script.",
                "inputs": {"task": "Analyze the encryption script and implement a decryption routine for the output."}
            }

        if last_artifacts and "browser_snapshot" in last_artifacts:
            forms = last_artifacts["browser_snapshot"].get("forms", [])
            has_login = any("user" in str(f).lower() or "pass" in str(f).lower() for f in forms)
            if has_login and last_status != "solved":
                return {
                    "next_action": "run_agent",
                    "target": "coding_agent",
                    "reasoning": "A login form was discovered in the browser snapshot. Pivoting to coding_agent to attempt an automated login bypass.",
                    "inputs": {"task": "Attempt SQLi login bypass or default credentials on the discovered form."}
                }

        # Decision Quality: Don't repeat the same failed agent unless a new hint was provided
        has_hint = "User Hint:" in challenge.get("description", "")
        if not has_hint:
            if last_agent == analysis.recommended_target and last_status != "solved":
                return {
                    "next_action": "stop",
                    "target": "none",
                    "reasoning": f"Specialist {last_agent} already attempted this task and did not find a solution. Stopping to prevent infinite loop.",
                    "inputs": {},
                }

            # Decision Quality: Don't repeat the same failed tool
            last_target = last_result.get("routing", {}).get("selected_target")
            if last_target == "browser_snapshot" and analysis.recommended_target == "browser_snapshot":
                return {
                    "next_action": "stop",
                    "target": "none",
                    "reasoning": "Browser snapshot already performed. No further information gathered. Stopping.",
                    "inputs": {},
                }

        if analysis.recommended_target == "crypto_agent":
            return {
                "next_action": "run_agent",
                "target": "crypto_agent",
                "reasoning": "Crypto challenge detected.",
                "inputs": {},
            }

        if analysis.recommended_target == "coding_agent":
            return {
                "next_action": "run_agent",
                "target": "coding_agent",
                "reasoning": "Coding challenge detected.",
                "inputs": {},
            }

        if analysis.recommended_target == "forensics_agent":
            return {
                "next_action": "run_agent",
                "target": "forensics_agent",
                "reasoning": "Forensics challenge detected.",
                "inputs": {},
            }

        if analysis.recommended_target == "reverse_agent":
            return {
                "next_action": "run_agent",
                "target": "reverse_agent",
                "reasoning": "Reverse engineering challenge detected.",
                "inputs": {},
            }

        if analysis.recommended_target == "osint_agent":
            return {
                "next_action": "run_agent",
                "target": "osint_agent",
                "reasoning": "OSINT challenge detected.",
                "inputs": {},
            }

        if analysis.recommended_target == "log_agent":
            return {
                "next_action": "run_agent",
                "target": "log_agent",
                "reasoning": "Log analysis challenge detected.",
                "inputs": {},
            }

        if analysis.recommended_target == "web_agent":
            return {
                "next_action": "run_agent",
                "target": "web_agent",
                "reasoning": "Web challenge detected.",
                "inputs": {},
            }

        if analysis.recommended_target == "docker_agent":
            return {
                "next_action": "run_agent",
                "target": "docker_agent",
                "reasoning": "Local Docker challenge context detected.",
                "inputs": {},
            }

        if analysis.recommended_target == "recon_agent":
            return {
                "next_action": "run_agent",
                "target": "recon_agent",
                "reasoning": "Reconnaissance requested for a live target.",
                "inputs": {},
            }

        if analysis.recommended_target == "browser_snapshot":
            return {
                "next_action": "run_tool",
                "target": "browser_snapshot",
                "reasoning": "Web challenge detected.",
                "inputs": {
                    "url": challenge.get("url") or challenge.get("target", {}).get("url", "")
                },
            }

        if analysis.recommended_target == "tony_htb_sql":
            return {
                "next_action": "run_tool",
                "target": "tony_htb_sql",
                "reasoning": "SQL injection likely.",
                "inputs": {
                    "url": challenge.get("url") or challenge.get("target", {}).get("url", "")
                },
            }

        return {
            "next_action": "stop",
            "target": "none",
            "reasoning": "No confident next step.",
            "inputs": {},
        }

    @staticmethod
    def _has_docker_context(files: List[str]) -> bool:
        for raw_path in files:
            path = os.path.expanduser(str(raw_path))
            if os.path.isfile(path) and os.path.basename(path).lower() == "dockerfile":
                return True
            if os.path.isdir(path):
                if os.path.exists(os.path.join(path, "Dockerfile")):
                    return True
        return False

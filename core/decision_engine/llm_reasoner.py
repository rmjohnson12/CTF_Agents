from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

from openai import OpenAI
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

_RETRYABLE_EXCEPTIONS = (ConnectionError, TimeoutError)
_MAX_LLM_RETRIES = 3
_LLM_BACKOFF_BASE = 1.0


class LLMReasoner:
    """
    Uses an LLM client for challenge analysis and action selection.

    Priority order for auto-configuration:
      1. Explicit client passed in
      2. NVAPI_KEY env var  → NVIDIA NIM (OpenAI-compatible, free tier available)
      3. OPENAI_API_KEY env var → OpenAI
      4. Heuristic fallback
    """

    def __init__(self, client: Optional[Any] = None, model: Optional[str] = None):
        if client is not None:
            self.client = client
            self.model = model or "gpt-4o"
        else:
            nvapi_key = os.getenv("NVAPI_KEY")
            openai_key = os.getenv("OPENAI_API_KEY")

            if nvapi_key:
                self.client = OpenAI(
                    api_key=nvapi_key,
                    base_url=_NVIDIA_NIM_BASE_URL,
                )
                self.model = model or _NVIDIA_DEFAULT_MODEL
            elif openai_key:
                self.client = OpenAI(api_key=openai_key)
                self.model = model or "gpt-4o"
            else:
                self.client = None
                self.model = model or "none"

    @property
    def is_available(self) -> bool:
        """Checks if the LLM client is configured and available."""
        return self.client is not None

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

        for attempt in range(1, _MAX_LLM_RETRIES + 1):
            try:
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
                logger.error("LLM call failed with non-retryable error: %s", exc)
                return ""

        return ""

    def _build_analysis_prompt(self, challenge: Dict[str, Any]) -> str:
        system_tools = challenge.get("metadata", {}).get("system_tools", [])
        tools_ctx = f"Available system tools: {', '.join(system_tools)}" if system_tools else ""

        return f"""
    You are analyzing a CTF challenge for routing and planning.
    {tools_ctx}

    Return ONLY valid JSON with this shape:
    {{
    "category_guess": "crypto|web|reverse|pwn|forensics|osint|log|misc|unknown",
    "confidence": 0.0,
    "reasoning": "short explanation",
    "recommended_target": "crypto_agent|browser_snapshot|tony_htb_sql|coding_agent|forensics_agent|reverse_agent|osint_agent|log_agent|none",
    "recommended_action": "run_agent|run_tool|stop",
    "detected_indicators": ["indicator1", "indicator2"]
    }}

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

        return f"""
    You are deciding the next step in a CTF agent workflow.
    {tools_ctx}

    Return ONLY valid JSON with this shape:
    {{
    "next_action": "run_agent|run_tool|stop",
    "target": "crypto_agent|browser_snapshot|tony_htb_sql|coding_agent|forensics_agent|reverse_agent|osint_agent|log_agent|none",
    "reasoning": "short explanation",
    "inputs": {{}}
    }}

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

        # Priority 1: Reverse Engineering (Source/Binary analysis)
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

        # Priority 2: Forensics (if files are present or forensics keywords found)
        if any(f.endswith('.pdf') or f.endswith('.pcap') for f in files) or \
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

        # Priority 3: Crypto / Decoding
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

        # Priority 4: SQLi
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

        # Priority 5: Log Analysis
        if any(f.endswith('.log') for f in files) or self._kw(text, "access log", "auth log", "server log"):
            indicators.append("log_terms")
            return ChallengeAnalysis(
                category_guess="log",
                confidence=0.84,
                reasoning="Detected log analysis indicators.",
                recommended_target="log_agent",
                recommended_action="run_agent",
                detected_indicators=indicators,
            )

        # Priority 6: Web
        url = challenge.get("url")
        if url or self._kw(text, "url", "http", "login", "form", "page", "cookie", "endpoint"):
            indicators.append("web_terms")

            # Heuristic pivot: If "inspect", "form", or "page" are used without specific attack keywords,
            # prefer browser_snapshot tool for initial reconnaissance.
            if self._kw(text, "inspect", "form", "page", "snapshot", "look at"):
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

        # Priority 7: Coding
        if self._kw(text, "script", "python", "automate", "program", "code", "algorithm"):
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

        # Pivot: If any step found a login form, let coding_agent try to bypass it
        if "browser_snapshot" in last_artifacts:
            forms = last_artifacts["browser_snapshot"].get("forms", [])
            has_login = any("user" in str(f).lower() or "pass" in str(f).lower() for f in forms)
            if has_login and last_status != "solved":
                return {
                    "next_action": "run_agent",
                    "target": "coding_agent",
                    "reasoning": "A login form was discovered in the browser snapshot. Pivoting to coding_agent to attempt an automated login bypass.",
                    "inputs": {"task": "Attempt SQLi login bypass or default credentials on the discovered form."}
                }

        # Decision Quality: Don't repeat the same failed agent
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

"""
ChallengeClassifier — heuristic challenge categorisation.

Standalone, dependency-free rule engine used by LLMReasoner as a
fallback when no LLM client is available and as an optional fast-path
for routing decisions.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class ChallengeAnalysis:
    category_guess: str
    confidence: float
    reasoning: str
    recommended_target: str
    recommended_action: str
    detected_indicators: List[str]


class ChallengeClassifier:
    """
    Rule-based challenge classifier.

    Inspects challenge name, description, hints, tags, and attached file
    extensions to produce a ChallengeAnalysis without any LLM call.
    Rules are ordered by specificity; the first matching rule wins.
    """

    def classify(self, challenge: Dict[str, Any]) -> ChallengeAnalysis:
        text = " ".join([
            challenge.get("name", ""),
            challenge.get("description", ""),
            " ".join(challenge.get("hints", [])),
            " ".join(challenge.get("tags", [])),
        ]).lower()

        indicators: List[str] = []
        files = challenge.get("files", [])

        # Docker context — must run before web/recon checks
        wants_docker_run = self._kw(
            text, "docker", "dockerfile", "container", "spawn", "run locally", "launch"
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

        # Network forensics (PCAP)
        if any(f.endswith((".pcap", ".pcapng")) for f in files) or self._kw(text, "pcap"):
            indicators.append("network_forensics")
            return ChallengeAnalysis(
                category_guess="forensics",
                confidence=0.96,
                reasoning="Detected PCAP files or network forensics keywords.",
                recommended_target="forensics_agent",
                recommended_action="run_agent",
                detected_indicators=indicators,
            )

        # Binary artifacts with forensics intent
        if (
            any(f.endswith((".bin", ".dat")) for f in files)
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

        # Live SSH forensics/rootkit triage. This must beat generic "ssh"
        # log-analysis routing because these prompts require connecting to a
        # lab host and inspecting dynamic loader/filesystem manipulation.
        if (
            challenge.get("category") == "forensics"
            and self._kw(text, "ssh")
            and self._kw(
                text,
                "rootkit", "library", "ld_preload", "preload",
                "linking", "filesystem", "hidden manipulation",
            )
        ):
            indicators.append("live_ssh_forensics")
            return ChallengeAnalysis(
                category_guess="forensics",
                confidence=0.95,
                reasoning="Detected live SSH forensics indicators for loader/rootkit analysis.",
                recommended_target="forensics_agent",
                recommended_action="run_agent",
                detected_indicators=indicators,
            )

        # Crypto — source-plus-ciphertext bundle or explicit keywords
        has_crypto_file_pair = (
            any(f.endswith((".enc", ".cipher", ".ct", ".out", ".txt")) for f in files)
            and any(f.endswith((".py", ".sage", ".js")) for f in files)
        )
        if (
            challenge.get("category") == "crypto"
            or has_crypto_file_pair
            or self._kw(
                text,
                "cipher", "decrypt", "decode", "encrypted",
                "xor", "aes", "caesar", "affine",
            )
        ):
            indicators.append("crypto_terms")
            return ChallengeAnalysis(
                category_guess="crypto",
                confidence=0.94,
                reasoning="Detected crypto wording or a source-plus-ciphertext challenge bundle.",
                recommended_target="crypto_agent",
                recommended_action="run_agent",
                detected_indicators=indicators,
            )

        # PWN / binary exploitation — before generic reverse so explicit pwn
        # challenges are not mis-routed to the reverse agent.
        has_elf = any(f.endswith(".elf") for f in files) or any(
            self._is_elf_file(f) for f in files
        )
        if (
            challenge.get("category") in ("pwn", "binary")
            or self._kw(text, "pwn", "overflow", "rop", "ret2libc", "shellcode")
            or (has_elf and self._kw(text, "exploit", "pwn", "overflow", "binary", "attack"))
        ):
            indicators.append("pwn_terms")
            return ChallengeAnalysis(
                category_guess="pwn",
                confidence=0.94,
                reasoning="Detected binary exploitation indicators.",
                recommended_target="pwn_agent",
                recommended_action="run_agent",
                detected_indicators=indicators,
            )

        # Reverse engineering
        if (
            has_elf
            or any(f.endswith((".py", ".exe", ".bin")) for f in files)
            or self._kw(text, "reverse", "source code", "analyze program", "authenticate the program")
        ):
            indicators.append("reverse_terms")
            return ChallengeAnalysis(
                category_guess="reverse",
                confidence=0.95,
                reasoning="Detected reverse engineering indicators or executable files.",
                recommended_target="reverse_agent",
                recommended_action="run_agent",
                detected_indicators=indicators,
            )

        # Forensics (generic — PDF, other binary formats, or explicit keywords)
        if any(f.endswith((".pdf", ".pcap", ".dat")) for f in files) or self._kw(
            text, "artifact", "extract", "binwalk", "forensics", "metadata", "exiftool"
        ):
            indicators.append("forensics_terms")
            return ChallengeAnalysis(
                category_guess="forensics",
                confidence=0.94,
                reasoning="Detected forensic indicators or provided files.",
                recommended_target="forensics_agent",
                recommended_action="run_agent",
                detected_indicators=indicators,
            )

        # Log analysis
        if (
            challenge.get("category") == "log"
            or any(f.endswith(".log") for f in files)
            or self._kw(
                text,
                "access log", "auth log", "server log",
                "brute force", "failed password", "ssh",
            )
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

        # Crypto — numerical encoding / password cracking
        if re.search(r"\b(?:\d{1,3}[\s,]+){3,}", text) or self._kw(
            text, "base64", "hex", "password", "rockyou", "crack"
        ):
            indicators.append("crypto_terms")
            return ChallengeAnalysis(
                category_guess="crypto",
                confidence=0.93,
                reasoning="Detected crypto/decoding indicators or numerical encoding.",
                recommended_target="crypto_agent",
                recommended_action="run_agent",
                detected_indicators=indicators,
            )

        # SQL injection
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

        # Web
        url = challenge.get("url")
        ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b"
        if url or re.search(ip_pattern, text) or self._kw(
            text, "url", "http", "login", "form", "page",
            "cookie", "endpoint", "jwt", "token", "session",
        ):
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

            if self._kw(
                text, "inspect", "form", "page", "snapshot", "look at",
                "source", "javascript", "js", "code", "analyze",
            ):
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

        # OSINT
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

        # Misc / coding
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

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _kw(text: str, *words: str) -> bool:
        """True if any word/phrase matches as a whole word in *text*."""
        return any(re.search(r"\b" + re.escape(w) + r"\b", text) for w in words)

    @staticmethod
    def _is_elf_file(path: str) -> bool:
        try:
            from tools.common.elf_utils import is_elf_binary
            return is_elf_binary(path)
        except Exception:
            return False

    @staticmethod
    def _has_docker_context(files: List[str]) -> bool:
        for raw_path in files:
            path = os.path.expanduser(str(raw_path))
            if os.path.isfile(path) and os.path.basename(path).lower() == "dockerfile":
                return True
            if os.path.isdir(path) and os.path.exists(os.path.join(path, "Dockerfile")):
                return True
        return False

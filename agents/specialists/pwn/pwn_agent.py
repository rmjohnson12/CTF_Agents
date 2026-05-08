"""PWN specialist agent.

Orchestration order for a binary challenge:
  1. checksec — identify mitigations
  2. Ghidra static analysis — functions, strings, imports (skipped if GHIDRA_HOME unset)
  3. angr symbolic execution — auto-find input for win/flag functions (skipped if angr missing)
     3b. Execute binary with payload, scan output for a real flag pattern.
         Payload goes to artifacts; only mark solved when a flag is confirmed.
  4. pwntools template — fallback exploitation scaffold + LLM strategy advice
"""
from __future__ import annotations

import logging
import os
import subprocess
from typing import Any, Dict, List, Optional

from agents.base_agent import BaseAgent, AgentType
from core.decision_engine.llm_reasoner import LLMReasoner
from core.utils.flag_utils import find_first_flag
from tools.common.elf_utils import is_elf_binary
from tools.pwn.pwntools_wrapper import PwntoolsWrapper

logger = logging.getLogger(__name__)

_PWN_KEYWORDS = frozenset([
    "overflow", "pwn", "exploit", "rop", "ret2libc", "shellcode",
    "buffer", "heap", "use-after-free", "uaf", "format string",
    "stack", "bypass", "binary", "reversing", "reverse",
])

_BINARY_EXTENSIONS = {".elf", ".bin", ".exe", ".out", ".o"}


def _is_binary(path: str) -> bool:
    return any(path.endswith(ext) for ext in _BINARY_EXTENSIONS) or is_elf_binary(path)


class PwnAgent(BaseAgent):
    """
    Specialist agent for advanced binary exploitation and symbolic reversing.

    Capabilities beyond BinaryExploitationAgent:
    - angr symbolic execution to auto-discover inputs for win conditions
    - Ghidra-assisted function discovery to feed angr targeting
    - Graceful degradation when optional tools (angr, Ghidra) are unavailable
    """

    def __init__(
        self,
        agent_id: str = "pwn_agent",
        reasoner: Optional[LLMReasoner] = None,
        pwn_tool: Optional[PwntoolsWrapper] = None,
    ) -> None:
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.reasoner = reasoner or LLMReasoner()
        self.pwn_tool = pwn_tool or PwntoolsWrapper()
        self.capabilities = [
            "symbolic_execution",
            "win_function_discovery",
            "buffer_overflow",
            "rop_chain_generation",
            "shellcode_injection",
            "format_string_exploitation",
            "heap_exploitation",
            "binary_mitigation_analysis",
            "ghidra_static_analysis",
            "kernel_exploitation",
            "race_conditions",
        ]

        # Lazy-loaded optional tools — instantiated on first use so missing
        # deps don't prevent the agent from loading.
        self._angr: Any = None
        self._ghidra: Any = None

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        description = challenge.get("description", "").lower()
        files = challenge.get("files", [])
        category = challenge.get("category", "").lower()

        has_binary = any(_is_binary(f) for f in files)
        has_keywords = any(kw in description for kw in _PWN_KEYWORDS)
        is_pwn_category = category in {"pwn", "binary", "reversing", "rev"}

        can_handle = has_binary or has_keywords or is_pwn_category
        confidence = 0.9 if can_handle else 0.1

        return {
            "agent_id": self.agent_id,
            "can_handle": can_handle,
            "confidence": confidence,
            "approach": (
                "Static analysis + symbolic execution + exploit generation"
                if can_handle else "None"
            ),
        }

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        steps: List[str] = []
        files = challenge.get("files", [])
        binaries = [f for f in files if _is_binary(f)]

        if not binaries:
            conn_info = challenge.get("connection_info")
            if not conn_info:
                return self._result(challenge, "failed", steps,
                                    error="No binary files or connection info found")
            steps.append(f"Remote-only challenge: {conn_info}")
            return self._result(challenge, "attempted", steps)

        binary = binaries[0]
        steps.append(f"Primary binary: {binary}")

        # Phase 1 — mitigations
        steps.extend(self._phase_checksec(binary))

        # Phase 2 — Ghidra static analysis
        ghidra_steps, ghidra_functions = self._phase_ghidra(binary)
        steps.extend(ghidra_steps)

        # Phase 3 — angr symbolic execution → payload
        angr_steps, payload = self._phase_angr(binary, ghidra_functions, challenge)
        steps.extend(angr_steps)

        if payload is not None:
            # Phase 3b — run binary with payload and look for a real flag
            run_steps, flag_str = self._phase_run_with_payload(binary, payload)
            steps.extend(run_steps)
            if flag_str:
                return self._result(challenge, "solved", steps, flag=flag_str)
            # Payload found but no flag confirmed — store as artifact
            return self._result(
                challenge, "attempted", steps,
                artifacts={"angr_payload": payload.hex()},
            )

        # Phase 4 — pwntools template + LLM fallback
        steps.extend(self._phase_pwntools_fallback(binary, challenge))

        return self._result(challenge, "attempted", steps)

    def get_capabilities(self) -> List[str]:
        return self.capabilities

    # ------------------------------------------------------------------
    # Phase helpers
    # ------------------------------------------------------------------

    def _phase_checksec(self, binary: str) -> List[str]:
        steps: List[str] = []
        steps.append("Running checksec...")
        mitigations = self.pwn_tool.run_checksec(binary)
        if "error" not in mitigations:
            steps.append(f"Mitigations: {mitigations}")
        else:
            steps.append(f"checksec unavailable: {mitigations['error']}")
        return steps

    def _phase_ghidra(self, binary: str) -> tuple[List[str], List[str]]:
        """Returns (steps, list_of_function_names)."""
        steps: List[str] = []
        function_names: List[str] = []

        ghidra = self._load_ghidra()
        if ghidra is None:
            steps.append("Ghidra skipped (GHIDRA_HOME not set or unavailable)")
            return steps, function_names

        steps.append("Running Ghidra headless analysis...")
        try:
            analysis = ghidra.analyze(binary, timeout_s=300)
            function_names = [f.name for f in analysis.functions]
            steps.append(
                f"Ghidra found {len(analysis.functions)} functions, "
                f"{len(analysis.strings)} strings, "
                f"{len(analysis.imports)} imports"
            )
            interesting = [
                n for n in function_names
                if any(kw in n.lower() for kw in ("win", "flag", "shell", "backdoor",
                                                   "success", "correct", "chall"))
            ]
            if interesting:
                steps.append(f"Interesting functions: {interesting}")
        except Exception as exc:
            steps.append(f"Ghidra analysis failed: {exc}")

        return steps, function_names

    def _phase_angr(
        self,
        binary: str,
        ghidra_functions: List[str],
        challenge: Dict[str, Any],
    ) -> tuple[List[str], Optional[bytes]]:
        """Returns (steps, stdin_payload_bytes_or_None)."""
        steps: List[str] = []

        angr_tool = self._load_angr()
        if angr_tool is None:
            steps.append("angr skipped (not installed — run: pip install angr)")
            return steps, None

        steps.append("Scanning binary for win/flag symbols via angr...")
        try:
            hits = angr_tool.find_win_symbols(binary)
        except Exception as exc:
            steps.append(f"Symbol scan failed: {exc}")
            return steps, None

        if not hits:
            # Supplement with any names Ghidra found
            for name in ghidra_functions:
                if any(kw in name.lower() for kw in ("win", "flag", "shell",
                                                      "backdoor", "success")):
                    from tools.pwn.angr_tool import SymbolHit
                    hits.append(SymbolHit(addr=0, name=name))

        if not hits:
            steps.append("No win/flag symbols found — skipping symbolic execution")
            return steps, None

        target = hits[0]
        steps.append(
            f"Targeting symbol '{target.name}' "
            f"(0x{target.addr:x} if resolved)"
        )

        result = (
            angr_tool.find_input(binary, find_addr=target.addr)
            if target.addr
            else angr_tool.find_input_by_symbol(binary, symbol_name=target.name)
        )

        steps.append(
            f"angr exploration completed in {result.duration_s:.1f}s — "
            f"{'found path' if result.found else 'no path found'}"
        )

        if result.found and result.stdin_input is not None:
            payload_preview = result.stdin_input[:80]
            try:
                readable = payload_preview.decode("utf-8", errors="replace")
            except Exception:
                readable = repr(payload_preview)
            steps.append(f"Payload (first 80 bytes): {readable!r}")
            return steps, result.stdin_input

        if result.error:
            steps.append(f"angr error: {result.error}")

        return steps, None

    def _phase_run_with_payload(
        self, binary: str, payload: bytes
    ) -> tuple[List[str], Optional[str]]:
        """
        Execute *binary* with *payload* piped to stdin, scan output for a flag.

        Returns (steps, flag_string_or_None).
        """
        steps: List[str] = []
        steps.append(f"Executing binary with angr payload ({len(payload)} bytes)...")
        try:
            if not os.access(binary, os.X_OK):
                current_mode = os.stat(binary).st_mode
                os.chmod(binary, current_mode | 0o700)
                steps.append("Binary was not executable; added user execute permission.")

            proc = subprocess.run(
                [binary],
                input=payload,
                capture_output=True,
                timeout=10,
            )
            output = (proc.stdout + proc.stderr).decode("utf-8", errors="replace")
            preview = output[:200].replace("\n", " ")
            steps.append(f"Binary output: {preview!r}")

            flag = find_first_flag(output)
            if flag:
                steps.append(f"Flag confirmed: {flag}")
                return steps, flag

            steps.append("No flag pattern found in binary output")

        except FileNotFoundError:
            steps.append(f"Binary not found or not executable: {binary}")
        except PermissionError:
            steps.append(f"Permission denied running binary: {binary}")
        except subprocess.TimeoutExpired:
            steps.append("Binary execution timed out (10s)")
        except Exception as exc:
            steps.append(f"Binary execution error: {exc}")

        return steps, None

    def _phase_pwntools_fallback(
        self, binary: str, challenge: Dict[str, Any]
    ) -> List[str]:
        steps: List[str] = []
        conn_info = challenge.get("connection_info")
        self.pwn_tool.generate_template(binary, conn_info)
        steps.append("Generated pwntools exploit template")

        if self.reasoner.is_available:
            steps.append("Requesting exploit strategy from LLM...")
            prompt = (
                f"Provide a brief exploit strategy for this binary challenge.\n"
                f"Binary: {binary}\n"
                f"Description: {challenge.get('description', 'N/A')}\n"
                f"Connection info: {conn_info or 'local only'}"
            )
            try:
                advice = self.reasoner._call_llm(prompt)
                steps.append(f"LLM strategy: {advice}")
            except Exception as exc:
                steps.append(f"LLM unavailable: {exc}")

        return steps

    # ------------------------------------------------------------------
    # Lazy loaders
    # ------------------------------------------------------------------

    def _load_angr(self) -> Any:
        if self._angr is not None:
            return self._angr
        try:
            from tools.pwn.angr_tool import AngrTool
            self._angr = AngrTool()
        except ImportError:
            self._angr = None
        return self._angr

    def _load_ghidra(self) -> Any:
        if self._ghidra is not None:
            return self._ghidra
        import os
        if not os.environ.get("GHIDRA_HOME"):
            return None
        try:
            from tools.pwn.headless_ghidra_tool import HeadlessGhidraTool
            self._ghidra = HeadlessGhidraTool()
        except Exception:
            self._ghidra = None
        return self._ghidra

    # ------------------------------------------------------------------
    # Result builder
    # ------------------------------------------------------------------

    @staticmethod
    def _result(
        challenge: Dict[str, Any],
        status: str,
        steps: List[str],
        flag: Optional[str] = None,
        artifacts: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "challenge_id": challenge.get("id"),
            "agent_id": "pwn_agent",
            "status": status,
            "steps": steps,
        }
        if flag is not None:
            out["flag"] = flag
        if artifacts:
            out["artifacts"] = artifacts
        if error:
            out["error"] = error
        return out

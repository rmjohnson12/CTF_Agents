"""
Reverse Engineering Specialist Agent

Handles both source-code analysis challenges (Python/C constraint solving)
and binary reversing challenges (ELF + encrypted-output patterns).
"""

import base64
import ctypes
import hashlib
import http.client
import io
import itertools
import logging
import os
import re
import shutil
import socket
import struct
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional

from agents.base_agent import BaseAgent, AgentType
from core.decision_engine.llm_reasoner import LLMReasoner
from core.utils.flag_utils import find_first_flag
from core.utils.security import SecurityPolicyError, assert_host_allowed
from tools.common.elf_utils import is_elf_binary, is_native_binary, is_pe_binary
from tools.common.python_tool import PythonTool

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# AES S-box / inverse S-box (for AES-NI instruction simulation)
# ---------------------------------------------------------------------------

_AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
_AES_INV_SBOX: List[int] = [0] * 256
for _i, _v in enumerate(_AES_SBOX):
    _AES_INV_SBOX[_v] = _i

# ---------------------------------------------------------------------------
# glibc rand() reimplementation
# ---------------------------------------------------------------------------
# glibc uses a degree-31 LFSR with a 310-call warmup after srand().
# macOS libc has a different algorithm so we can't use ctypes directly.

_DEG_3 = 31
_SEP_3 = 3


def _glibc_srand(seed: int):
    """Return (state, fptr, rptr) after seeding glibc's rand()."""
    state = [0] * _DEG_3
    state[0] = int(seed) & 0xFFFFFFFF
    if state[0] == 0:
        state[0] = 1
    word = state[0]
    for i in range(1, _DEG_3):
        word = (word % 127773) * 16807 - (word // 127773) * 2836
        if word < 0:
            word += 2147483647
        state[i] = word
    fptr, rptr = _SEP_3, 0
    # warmup
    for _ in range(10 * _DEG_3):
        fptr, rptr = _glibc_rand_step(state, fptr, rptr)
    return state, fptr, rptr


def _glibc_rand_step(state: list, fptr: int, rptr: int):
    """Advance one step and return (new_fptr, new_rptr). Mutates state."""
    val = ctypes.c_int32(state[fptr] + state[rptr]).value
    state[fptr] = val
    fptr = (fptr + 1) % _DEG_3
    rptr = (rptr + 1) % _DEG_3
    return fptr, rptr


def _glibc_rand(state: list, fptr: int, rptr: int):
    """Return (rand_value, new_fptr, new_rptr)."""
    val = ctypes.c_int32(state[fptr] + state[rptr]).value
    state[fptr] = val
    result = (val >> 1) & 0x7FFFFFFF
    fptr = (fptr + 1) % _DEG_3
    rptr = (rptr + 1) % _DEG_3
    return result, fptr, rptr


def _ror8(b: int, n: int) -> int:
    n &= 7
    return ((b >> n) | (b << (8 - n))) & 0xFF


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class ReverseEngineeringAgent(BaseAgent):
    """
    Specialist agent for reverse engineering challenges.

    Handles:
    - Source code analysis (Python/C constraint solving)
    - ELF + encrypted-file ransomware-style challenges:
        * Reads the seed from the first 4 bytes of the .enc file
        * Simulates glibc rand() to reverse XOR+ROL encryption
    - LLM fallback for complex logic when a model is configured
    """

    def __init__(
        self,
        agent_id: str = "reverse_agent",
        reasoner: Optional[LLMReasoner] = None,
        python_tool: Optional[PythonTool] = None,
    ):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.reasoner = reasoner or LLMReasoner()
        self.python_tool = python_tool or PythonTool()
        self.capabilities = [
            "reverse_engineering",
            "source_code_analysis",
            "python_analysis",
            "decompilation",
            "static_analysis",
            "verification",
            "encryptor_reversal",
            "crackme_rodata_extraction",
            "indexed_xor_phrase",
            "substitution_table_vm",
            "godot_game_loader",
            "remote_arm_emulation",
        ]

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        description = challenge.get("description", "").lower()
        files = challenge.get("files", [])
        tags = " ".join(challenge.get("tags", [])).lower()

        has_binary = any(is_native_binary(f) for f in files)
        has_enc = any(f.endswith(".enc") or f.endswith(".encrypted") for f in files)
        has_source = any(f.endswith((".py", ".c", ".cpp", ".js")) for f in files)

        indicators = ["reverse", "analyze", "source code", "authenticate", "encrypt", "ransomware"]
        keyword_hit = any(w in description or w in tags for w in indicators)

        can_handle = has_binary or has_enc or has_source or keyword_hit or \
                     challenge.get("category") in ("reverse", "rev", "reversing")

        detected = [w for w in indicators if w in description or w in tags]
        if has_binary:
            detected.append("elf_binary")
        if has_enc:
            detected.append("enc_file")

        return {
            "agent_id": self.agent_id,
            "can_handle": can_handle,
            "confidence": 0.9 if can_handle else 0.2,
            "approach": self._plan_approach(detected),
        }

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        steps: List[str] = []
        files = challenge.get("files", [])

        # Remote reversing services sometimes stream machine code instead of
        # providing a local artifact. Handle that protocol before the normal
        # file-required strategies.
        if self._looks_like_remote_arm_challenge(challenge):
            return self._solve_remote_arm_register_challenge(challenge, steps)

        if not files:
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "failed",
                "flag": None,
                "steps": ["No files provided for analysis"],
            }

        # Unpack any UPX-packed binaries before analysis
        effective_files = [self._unpack_upx(f, steps) for f in files]

        binaries = [f for f in effective_files if is_native_binary(f)]
        enc_files = [f for f in effective_files if f.endswith(".enc") or f.endswith(".encrypted")]
        source_files = [f for f in effective_files if f.endswith((".py", ".c", ".cpp", ".js", ".gd"))]

        # --- Strategy 0: Godot game-loader bundles (.exe + encrypted .pck) ---
        result = self._try_godot_game_loader(effective_files, challenge, steps)
        if result:
            return result

        # --- Strategy 1: encryptor binary + .enc output ---
        if binaries and enc_files:
            result = self._try_encryptor_reversal(binaries[0], enc_files[0], challenge, steps)
            if result:
                return result

        # --- Strategy 2: crackme — password stored in .rodata fragments ---
        for binary in binaries:
            result = self._try_rodata_password(binary, challenge, steps)
            if result:
                return result

        # --- Strategy 3: numeric-encoded flag (char_code * N stored as integers) ---
        for binary in binaries:
            result = self._try_numeric_encoding(binary, challenge, steps)
            if result:
                return result

        # --- Strategy 4: substitution-table bytecode VM verifier ---
        for binary in binaries:
            result = self._try_substitution_table_vm(binary, challenge, steps)
            if result:
                return result

        # --- Strategy 5: indexed XOR/add phrase verifier ---
        for binary in binaries:
            result = self._try_indexed_xor_phrase(binary, challenge, steps)
            if result:
                return result

        # --- Strategy 6: .NET assembly with encrypted embedded resource ---
        for binary in binaries:
            if is_pe_binary(binary):
                result = self._try_dotnet_resource(binary, challenge, steps)
                if result:
                    return result

        # --- Strategy 7: AES-NI self-decrypting shellcode (PE) ---
        for binary in binaries:
            if is_pe_binary(binary):
                result = self._try_aes_ni_shellcode(binary, challenge, steps)
                if result:
                    return result

        # --- Strategy 8: source code constraint solving ---
        for file_path in source_files:
            result = self._try_source_analysis(file_path, challenge, steps)
            if result:
                return result

        # --- Strategy 9: strings + optional LLM on any remaining file ---
        for file_path in effective_files:
            steps.append(f"Running strings on {file_path}")
            try:
                r = subprocess.run(
                    ["strings", "-n", "6", file_path],
                    capture_output=True, timeout=15,
                )
                printable = r.stdout.decode("utf-8", errors="replace")
                flag = find_first_flag(printable)
                if flag:
                    steps.append(f"Flag found in strings output: {flag}")
                    return self._result(challenge, "solved", steps, flag=flag)
                if (
                    self.reasoner.is_available
                    and printable.strip()
                    and os.getenv("CTF_AGENTS_ENABLE_REVERSE_LLM_FALLBACK") == "1"
                ):
                    steps.append("Requesting LLM analysis of strings output...")
                    prompt = (
                        f"Binary strings output from a CTF reverse engineering challenge "
                        f"(description: {challenge.get('description', '')[:300]}):\n\n"
                        f"{printable[:3000]}\n\n"
                        "Identify any encryption algorithm, keys, or flags."
                    )
                    try:
                        advice = self.reasoner._call_llm(prompt)
                        steps.append(f"LLM analysis: {advice[:500]}")
                        flag = find_first_flag(advice)
                        if flag:
                            return self._result(challenge, "solved", steps, flag=flag)
                    except Exception as exc:
                        steps.append(f"LLM unavailable: {exc}")
                elif self.reasoner.is_available and printable.strip():
                    steps.append(
                        "Skipping reverse LLM strings fallback by default; "
                        "set CTF_AGENTS_ENABLE_REVERSE_LLM_FALLBACK=1 to enable."
                    )
            except Exception as exc:
                logger.debug("strings failed on %s: %s", file_path, exc)
                steps.append(f"strings error on {file_path}: {exc}")

        return self._result(challenge, "attempted", steps)

    # ------------------------------------------------------------------
    # Remote ARM register emulation
    # ------------------------------------------------------------------

    @staticmethod
    def _looks_like_remote_arm_challenge(challenge: Dict[str, Any]) -> bool:
        text = " ".join(
            str(challenge.get(key, ""))
            for key in ("name", "title", "description", "tags", "category")
        ).lower()
        arm_signal = bool(re.search(r"\barm(?:32)?\b|arm instructions?|arms race", text))
        register_signal = bool(re.search(r"\br0\b|register|machine code|instructions?", text))
        return arm_signal and register_signal and ReverseEngineeringAgent._remote_endpoint(challenge) is not None

    @staticmethod
    def _remote_endpoint(challenge: Dict[str, Any]) -> Optional[tuple[str, int]]:
        values: List[str] = []
        for key in ("url", "connection_info", "remote", "target"):
            value = challenge.get(key)
            if isinstance(value, dict):
                host = value.get("host") or value.get("hostname")
                port = value.get("port")
                if host and port:
                    try:
                        return str(host), int(port)
                    except (TypeError, ValueError):
                        pass
                values.extend(str(item) for item in value.values() if item)
            elif value:
                values.append(str(value))
        values.append(str(challenge.get("description", "")))

        for value in values:
            match = re.search(r"(?<![\w.-])([A-Za-z0-9.-]+):(\d{1,5})(?!\d)", value)
            if match and 0 < int(match.group(2)) <= 65535:
                return match.group(1), int(match.group(2))
            if "://" in value:
                parsed = urlparse(value)
                try:
                    if parsed.hostname and parsed.port:
                        return parsed.hostname, parsed.port
                except ValueError:
                    pass
        return None

    def _solve_remote_arm_register_challenge(
        self,
        challenge: Dict[str, Any],
        steps: List[str],
    ) -> Dict[str, Any]:
        endpoint = self._remote_endpoint(challenge)
        if endpoint is None:
            steps.append("Remote ARM challenge detected, but no host and port were found.")
            return self._result(challenge, "failed", steps)
        host, port = endpoint
        try:
            assert_host_allowed(host, port=port)
        except SecurityPolicyError as exc:
            steps.append(f"Remote ARM target blocked by network policy: {exc}")
            return self._result(challenge, "failed", steps)

        steps.append(f"Detected bounded remote ARM register-emulation protocol at {host}:{port}.")
        self.emit_progress(
            status="running",
            step_title="ARM emulation protocol detected",
            step_description=f"Connecting to authorized target {host}:{port}",
            challenge=challenge,
            confidence=0.95,
        )
        prompt_re = re.compile(
            rb"Level\s+(\d+)/(\d+):\s*([0-9a-fA-F]+).*?Register\s+r0:\s*",
            re.DOTALL,
        )
        buffer = b""
        total_received = 0
        completed = 0
        expected_total: Optional[int] = None
        max_levels = 100
        max_blob_bytes = 1024 * 1024
        max_received = 8 * 1024 * 1024

        try:
            with socket.create_connection((host, port), timeout=8) as connection:
                connection.settimeout(8)
                while completed < max_levels:
                    match = prompt_re.search(buffer)
                    if match is None:
                        chunk = connection.recv(65536)
                        if not chunk:
                            break
                        total_received += len(chunk)
                        if total_received > max_received:
                            raise ValueError("remote transcript exceeded the 8 MiB safety limit")
                        buffer += chunk
                        continue

                    level, total = int(match.group(1)), int(match.group(2))
                    code_hex = match.group(3)
                    buffer = buffer[match.end():]
                    if total < 1 or total > max_levels or level < 1 or level > total:
                        raise ValueError(f"invalid level counter {level}/{total}")
                    if expected_total is None:
                        expected_total = total
                        steps.append(f"Service requested {total} ARM emulation levels.")
                    elif total != expected_total:
                        raise ValueError("remote level count changed during the run")
                    if len(code_hex) % 8 != 0 or len(code_hex) // 2 > max_blob_bytes:
                        raise ValueError("ARM code blob is malformed or exceeds the 1 MiB limit")

                    r0 = self._emulate_arm_r0(bytes.fromhex(code_hex.decode("ascii")))
                    connection.sendall(f"{r0:#x}\n".encode("ascii"))
                    completed += 1
                    if level == 1 or level == total or level % 10 == 0:
                        steps.append(f"Emulated level {level}/{total}; submitted r0={r0:#x}.")
                        self.emit_progress(
                            status="running",
                            step_title=f"ARM level {level}/{total}",
                            step_description="Emulated A32 instructions and submitted the final r0 value.",
                            challenge=challenge,
                            confidence=0.98,
                        )

                    if level == total:
                        while len(buffer) < 65536:
                            try:
                                chunk = connection.recv(65536)
                            except socket.timeout:
                                break
                            if not chunk:
                                break
                            buffer += chunk
                        flag = find_first_flag(buffer.decode("utf-8", errors="replace"))
                        if flag:
                            steps.append(f"Flag received after completing {completed} levels.")
                            self.emit_progress(
                                status="solved",
                                step_title="Remote ARM challenge solved",
                                step_description=f"Completed all {completed} emulation levels.",
                                challenge=challenge,
                                confidence=1.0,
                                final_flag=flag,
                            )
                            return self._result(challenge, "solved", steps, flag=flag)
                        raise ValueError("final response did not contain a recognized flag")
        except ImportError as exc:
            steps.append(f"Unicorn ARM emulator is unavailable: {exc}")
        except (OSError, ValueError, RuntimeError) as exc:
            steps.append(f"Remote ARM emulation failed after {completed} levels: {exc}")

        return self._result(challenge, "attempted", steps)

    @staticmethod
    def _emulate_arm_r0(code: bytes) -> int:
        """Execute bounded little-endian A32 code and return unsigned r0."""
        from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc
        from unicorn.arm_const import UC_ARM_REG_R0

        if not code or len(code) % 4:
            raise ValueError("A32 code must contain complete 4-byte instructions")
        base = 0x10000
        mapped_size = ((len(code) + 0xFFF) // 0x1000) * 0x1000
        emulator = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        emulator.mem_map(base, mapped_size)
        emulator.mem_write(base, code)
        instruction_count = len(code) // 4
        emulator.emu_start(
            base,
            base + len(code),
            timeout=1_000_000,
            count=max(1_000, instruction_count * 4),
        )
        return int(emulator.reg_read(UC_ARM_REG_R0)) & 0xFFFFFFFF

    # ------------------------------------------------------------------
    # Strategy 0: Godot game loader / encrypted PCK recovery
    # ------------------------------------------------------------------

    def _try_godot_game_loader(
        self,
        files: List[str],
        challenge: Dict[str, Any],
        steps: List[str],
    ) -> Optional[Dict[str, Any]]:
        exe_files = [f for f in files if f.lower().endswith(".exe")]
        pck_files = [f for f in files if f.lower().endswith(".pck")]
        gd_files = [f for f in files if f.lower().endswith(".gd")]

        if not (pck_files or gd_files):
            return None

        steps.append("Checking for Godot game-loader indicators.")
        recovered_scripts = list(gd_files)

        if exe_files and pck_files:
            key = self._extract_godot_pck_key_from_pe(exe_files[0], steps, pck_files[0])
            if key:
                steps.append(f"Extracted Godot PCK AES key: {key}")
                recovered_scripts.extend(self._recover_godot_scripts_native(pck_files[0], key, steps))
                if not recovered_scripts:
                    recovered_scripts.extend(self._recover_godot_scripts_with_gdre(pck_files[0], key, steps))
            else:
                steps.append("Could not extract a Godot PCK key from the executable.")

        for script_path in sorted(set(recovered_scripts)):
            try:
                script_text = open(script_path, "r", encoding="utf-8", errors="replace").read()
            except OSError:
                continue

            decoded = self._decode_godot_loader_script(script_text)
            if not decoded:
                continue

            steps.append(f"Decoded Godot loader script: {script_path}")
            if decoded.get("target_host"):
                steps.append(f"C2 host from script: {decoded['target_host']}")
            if decoded.get("payload_path"):
                steps.append(f"Payload path from script: /{decoded['payload_path']}")
            if decoded.get("flag_tail"):
                steps.append(f"Decoded second flag half: {decoded['flag_tail']}")
            if decoded.get("cookie"):
                steps.append("Decoded decimal-joined cookie value from GDScript arrays.")

            flag = self._fetch_godot_loader_flag(challenge, decoded, steps)
            if flag:
                return self._result(challenge, "solved", steps, flag=flag)

            flag_tail = decoded.get("flag_tail")
            if flag_tail:
                steps.append("Only recovered the second flag half; first half is still required.")
                return self._result(
                    challenge,
                    "attempted",
                    steps,
                    artifacts={"partial_flag_tail": flag_tail},
                )

        return None

    @staticmethod
    def _decode_godot_loader_script(script_text: str) -> Optional[Dict[str, str]]:
        env: Dict[str, List[int]] = {}
        statements = re.split(r";|\n", script_text)

        for raw_stmt in statements:
            stmt = raw_stmt.strip()
            if not stmt:
                continue
            if stmt.startswith("var "):
                stmt = stmt[4:].strip()

            append_match = re.match(r"^([A-Za-z_]\w*)\.append_array\((\[.*\])\)$", stmt)
            if append_match:
                env.setdefault(append_match.group(1), []).extend(
                    ReverseEngineeringAgent._parse_godot_int_array(append_match.group(2))
                )
                continue

            assign_match = re.match(r"^([A-Za-z_]\w*)\s*=\s*(.+)$", stmt)
            if assign_match:
                name, expr = assign_match.groups()
                value = ReverseEngineeringAgent._eval_godot_array_expr(expr, env)
                if value is not None:
                    env[name] = value

        def b64_var(name: str) -> Optional[str]:
            if name not in env:
                return None
            try:
                raw = "".join(chr(value) for value in env[name])
                return base64.b64decode(raw).decode("utf-8", errors="replace")
            except Exception:
                return None

        decoded = {
            "target_host": b64_var("jkoq"),
            "payload_path": b64_var("ioqw"),
            "flag_tail": b64_var("loap"),
        }
        if "aklq" in env and "paic" in env:
            decoded["cookie"] = "".join(str(value) for value in env["aklq"] + env["paic"])

        return {key: value for key, value in decoded.items() if value}

    @staticmethod
    def _parse_godot_int_array(array_text: str) -> List[int]:
        values = []
        for token in array_text.strip()[1:-1].split(","):
            token = token.strip()
            if not token:
                continue
            values.append(int(token, 0))
        return values

    @staticmethod
    def _eval_godot_array_expr(expr: str, env: Dict[str, List[int]]) -> Optional[List[int]]:
        parts = ReverseEngineeringAgent._split_godot_concat(expr)
        if not parts:
            return None

        output: List[int] = []
        for part in parts:
            part = part.strip()
            if part.startswith("[") and part.endswith("]"):
                output.extend(ReverseEngineeringAgent._parse_godot_int_array(part))
            elif re.match(r"^[A-Za-z_]\w*$", part) and part in env:
                output.extend(env[part])
            else:
                return None
        return output

    @staticmethod
    def _split_godot_concat(expr: str) -> List[str]:
        parts: List[str] = []
        start = depth = 0
        for idx, char in enumerate(expr):
            if char == "[":
                depth += 1
            elif char == "]":
                depth -= 1
            elif char == "+" and depth == 0:
                parts.append(expr[start:idx])
                start = idx + 1
        parts.append(expr[start:])
        return [part.strip() for part in parts if part.strip()]

    def _fetch_godot_loader_flag(
        self,
        challenge: Dict[str, Any],
        decoded: Dict[str, str],
        steps: List[str],
    ) -> Optional[str]:
        url = challenge.get("url")
        target_host = decoded.get("target_host")
        payload_path = decoded.get("payload_path")
        cookie = decoded.get("cookie")
        flag_tail = decoded.get("flag_tail")
        if not (url and target_host and payload_path and cookie and flag_tail):
            return None

        parsed = urlparse(url if re.match(r"^https?://", url) else f"http://{url}")
        if parsed.scheme != "http" or not parsed.hostname:
            return None

        port = parsed.port or 80
        body = (
            '{"os_name":"Windows","processor_name":"Generic","cpu_cores":4,'
            '"is_64bit":true,"locale":"en_US","user_dir":"user://"}'
        )
        headers = {
            "Host": target_host,
            "User-Agent": "GodotEngine/4.1.1.stable (Windows)",
            "Content-Type": "application/json",
        }

        try:
            conn = http.client.HTTPConnection(parsed.hostname, port, timeout=10)
            conn.request("POST", "/enum", body=body, headers=headers)
            response = conn.getresponse()
            response.read()
            steps.append(f"POST /enum returned HTTP {response.status}.")
            conn.close()

            conn = http.client.HTTPConnection(parsed.hostname, port, timeout=15)
            get_headers = {
                "Host": target_host,
                "User-Agent": "GodotEngine/4.1.1.stable (Windows)",
                "Cookie": cookie,
            }
            conn.request("GET", f"/{payload_path}", headers=get_headers)
            response = conn.getresponse()
            payload = response.read(128)
            half_flag = response.getheader("X-Half-Flag")
            steps.append(f"GET /{payload_path} returned HTTP {response.status}.")
            conn.close()
            if half_flag:
                steps.append(f"Recovered first flag half from X-Half-Flag: {half_flag}")
                return half_flag + flag_tail
            if response.status == 200:
                flag = find_first_flag(payload.decode("utf-8", errors="replace"))
                if flag:
                    return flag
        except Exception as exc:
            steps.append(f"Godot C2 request failed: {exc}")

        return None

    @staticmethod
    def _recover_godot_scripts_with_gdre(pck_file: str, key: str, steps: List[str]) -> List[str]:
        gdre = ReverseEngineeringAgent._find_gdre_tool()
        if not gdre:
            steps.append("GDRE Tools not found; skipping encrypted PCK script recovery.")
            return []

        output_dir = tempfile.mkdtemp(prefix="ctf_agents_godot_")
        try:
            result = subprocess.run(
                [
                    gdre,
                    "--headless",
                    f"--recover={pck_file}",
                    f"--key={key}",
                    f"--output={output_dir}",
                    "--scripts-only",
                ],
                capture_output=True,
                text=True,
                timeout=45,
            )
        except Exception as exc:
            steps.append(f"GDRE recovery failed: {exc}")
            return []

        if result.returncode != 0:
            steps.append(f"GDRE recovery exited with {result.returncode}: {(result.stderr or result.stdout)[:200]}")
            return []

        scripts = [str(path) for path in Path(output_dir).rglob("*.gd")]
        steps.append(f"Recovered {len(scripts)} GDScript file(s) with GDRE Tools.")
        return scripts

    @staticmethod
    def _find_gdre_tool() -> Optional[str]:
        candidates = [
            os.environ.get("GDRE_TOOLS"),
            shutil.which("gdre_tools"),
            shutil.which("gdre"),
            "/tmp/gdre/Godot RE Tools.app/Contents/MacOS/Godot RE Tools",
            "/Applications/Godot RE Tools.app/Contents/MacOS/Godot RE Tools",
        ]
        for candidate in candidates:
            if candidate and os.path.exists(candidate):
                return candidate
        return None

    @staticmethod
    def _recover_godot_scripts_native(pck_file: str, key_hex: str, steps: List[str]) -> List[str]:
        try:
            from Crypto.Cipher import AES
        except Exception:
            steps.append("pycryptodome not installed; cannot natively extract encrypted PCK scripts.")
            return []

        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            steps.append("Godot PCK key is not valid hex; skipping native extraction.")
            return []

        try:
            with open(pck_file, "rb") as handle:
                handle.seek(20)
                _pack_flags = struct.unpack("<I", handle.read(4))[0]
                file_base = struct.unpack("<Q", handle.read(8))[0]

                handle.seek(96)
                file_count = struct.unpack("<I", handle.read(4))[0]
                md5_expected = handle.read(16)
                dir_len = struct.unpack("<Q", handle.read(8))[0]
                iv = handle.read(16)
                encrypted_dir = handle.read(ReverseEngineeringAgent._align16(dir_len))
        except Exception as exc:
            steps.append(f"Could not read Godot PCK directory metadata: {exc}")
            return []

        try:
            cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
            directory = cipher.decrypt(encrypted_dir)[:dir_len]
        except Exception as exc:
            steps.append(f"Could not decrypt Godot PCK directory: {exc}")
            return []

        if hashlib.md5(directory).digest() != md5_expected:
            steps.append("Native Godot PCK directory decrypt failed MD5 validation.")
            return []

        entries = ReverseEngineeringAgent._parse_godot_pck_directory(directory, file_count)
        if not entries:
            steps.append("Native Godot PCK directory parsed zero files.")
            return []

        output_dir = Path(tempfile.mkdtemp(prefix="ctf_agents_godot_native_"))
        recovered: List[str] = []
        try:
            with open(pck_file, "rb") as handle:
                for path, file_offset, file_size, flags in entries:
                    clean_path = path.replace("res://", "", 1).replace("user://", "", 1).strip("\0")
                    if not clean_path or ".." in Path(clean_path).parts:
                        continue

                    handle.seek(file_base + file_offset)
                    if flags & 1:
                        header = handle.read(40)
                        if len(header) < 40:
                            continue
                        file_len = struct.unpack("<Q", header[16:24])[0]
                        ciphertext = handle.read(ReverseEngineeringAgent._align16(file_len))
                        file_bytes = ReverseEngineeringAgent._decrypt_godot_pck_file(
                            key, header + ciphertext, steps
                        )
                    else:
                        file_bytes = handle.read(file_size)

                    if not file_bytes:
                        continue

                    local_path = output_dir / clean_path
                    local_path.parent.mkdir(parents=True, exist_ok=True)
                    local_path.write_bytes(file_bytes)
                    if local_path.suffix == ".gd":
                        recovered.append(str(local_path))
        except Exception as exc:
            steps.append(f"Native Godot PCK extraction failed: {exc}")
            return recovered

        steps.append(f"Recovered {len(recovered)} GDScript file(s) with native PCK extraction.")
        return recovered

    @staticmethod
    def _decrypt_godot_pck_file(key: bytes, blob: bytes, steps: List[str]) -> Optional[bytes]:
        try:
            from Crypto.Cipher import AES
        except Exception:
            return None

        if len(blob) < 40:
            return None
        md5_expected = blob[:16]
        file_len = struct.unpack("<Q", blob[16:24])[0]
        iv = blob[24:40]
        ciphertext = blob[40:]
        try:
            cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
            plaintext = cipher.decrypt(ciphertext)[:file_len]
        except Exception:
            return None
        if hashlib.md5(plaintext).digest() != md5_expected:
            steps.append("Warning: encrypted Godot PCK file failed MD5 validation after decrypt.")
        return plaintext

    @staticmethod
    def _parse_godot_pck_directory(directory: bytes, file_count: int) -> List[tuple[str, int, int, int]]:
        entries: List[tuple[str, int, int, int]] = []
        offset = 0
        for _ in range(file_count):
            if offset + 4 > len(directory):
                break
            path_len = struct.unpack("<I", directory[offset : offset + 4])[0]
            offset += 4
            if path_len <= 0 or offset + path_len > len(directory):
                break
            path = directory[offset : offset + path_len].decode("utf-8", errors="replace").strip("\0")
            offset += path_len
            if offset + 36 > len(directory):
                break
            file_offset, file_size = struct.unpack("<QQ", directory[offset : offset + 16])
            offset += 16
            offset += 16  # per-file MD5
            flags = struct.unpack("<I", directory[offset : offset + 4])[0]
            offset += 4
            entries.append((path, file_offset, file_size, flags))
        return entries

    @staticmethod
    def _align16(value: int) -> int:
        return value if value % 16 == 0 else value + (16 - value % 16)

    @staticmethod
    def _extract_godot_pck_key_from_pe(
        exe_file: str,
        steps: List[str],
        pck_file: Optional[str] = None,
    ) -> Optional[str]:
        try:
            data = open(exe_file, "rb").read()
        except OSError:
            return None

        try:
            image_base, sections = ReverseEngineeringAgent._parse_pe_image(data)
        except Exception as exc:
            steps.append(f"Could not parse PE headers for Godot key extraction: {exc}")
            return None

        text = next((section for section in sections if section["name"] == ".text"), None)
        rdata = next((section for section in sections if section["name"] == ".rdata"), None)
        if not text or not rdata:
            return None

        anchors = [
            b"Can't open encrypted pack directory.",
            b"Can't open encrypted pack-referenced file '%s'.",
            b'Condition "fae.is_null()" is true.',
            b"GDScript::load_byte_code",
        ]

        for anchor in anchors:
            idx = data.find(anchor, rdata["raw"], rdata["raw"] + rdata["raw_size"])
            while idx != -1:
                anchor_va = image_base + rdata["vaddr"] + (idx - rdata["raw"])
                lea_va = ReverseEngineeringAgent._find_pe_lea_to_va(data, image_base, text, anchor_va)
                if lea_va:
                    blob_va = ReverseEngineeringAgent._find_godot_key_blob_near(data, image_base, sections, text, lea_va)
                    if blob_va:
                        blob = ReverseEngineeringAgent._pe_read_va(data, image_base, sections, blob_va, 32)
                        if blob:
                            return blob.hex().upper()
                idx = data.find(anchor, idx + 1, rdata["raw"] + rdata["raw_size"])

        if pck_file:
            key = ReverseEngineeringAgent._scan_pe_sections_for_godot_pck_key(data, sections, pck_file, steps)
            if key:
                return key

        return None

    @staticmethod
    def _scan_pe_sections_for_godot_pck_key(
        pe_data: bytes,
        sections: List[Dict[str, int | str]],
        pck_file: str,
        steps: List[str],
    ) -> Optional[str]:
        try:
            from Crypto.Cipher import AES
        except Exception:
            steps.append("pycryptodome not installed; cannot scan PE sections for Godot PCK keys.")
            return None

        try:
            with open(pck_file, "rb") as handle:
                handle.seek(96)
                _file_count = struct.unpack("<I", handle.read(4))[0]
                md5_expected = handle.read(16)
                dir_len = struct.unpack("<Q", handle.read(8))[0]
                iv = handle.read(16)
                encrypted_dir = handle.read(ReverseEngineeringAgent._align16(dir_len))
        except Exception as exc:
            steps.append(f"Could not read PCK metadata for section key scan: {exc}")
            return None

        for section in sections:
            if str(section["name"]) not in (".data", ".rdata"):
                continue
            raw = int(section["raw"])
            raw_size = int(section["raw_size"])
            section_data = pe_data[raw : raw + raw_size]
            for offset in range(0, max(0, len(section_data) - 31)):
                key = section_data[offset : offset + 32]
                if key.count(b"\0") > 8:
                    continue
                try:
                    cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
                    directory = cipher.decrypt(encrypted_dir)[:dir_len]
                except Exception:
                    continue
                if hashlib.md5(directory).digest() != md5_expected:
                    continue
                steps.append(
                    "Validated Godot PCK key by scanning PE data sections and matching directory MD5."
                )
                return key.hex().upper()

        return None

    @staticmethod
    def _parse_pe_image(data: bytes) -> tuple[int, List[Dict[str, int | str]]]:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        opt_off = pe_off + 24
        opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
        section_count = struct.unpack_from("<H", data, pe_off + 6)[0]
        magic = struct.unpack_from("<H", data, opt_off)[0]
        image_base = struct.unpack_from("<Q" if magic == 0x20B else "<I", data, opt_off + 24)[0]
        sect_off = opt_off + opt_size
        sections: List[Dict[str, int | str]] = []
        for idx in range(section_count):
            base = sect_off + idx * 40
            name = data[base : base + 8].split(b"\0", 1)[0].decode("ascii", errors="replace")
            sections.append({
                "name": name,
                "vaddr": struct.unpack_from("<I", data, base + 12)[0],
                "vsize": struct.unpack_from("<I", data, base + 8)[0],
                "raw": struct.unpack_from("<I", data, base + 20)[0],
                "raw_size": struct.unpack_from("<I", data, base + 16)[0],
            })
        return image_base, sections

    @staticmethod
    def _pe_va_to_off(image_base: int, sections: List[Dict[str, int | str]], va: int) -> Optional[int]:
        rva = va - image_base
        for section in sections:
            start = int(section["vaddr"])
            size = max(int(section["vsize"]), int(section["raw_size"]))
            if start <= rva < start + size:
                return int(section["raw"]) + (rva - start)
        return None

    @staticmethod
    def _pe_read_va(
        data: bytes,
        image_base: int,
        sections: List[Dict[str, int | str]],
        va: int,
        size: int,
    ) -> Optional[bytes]:
        offset = ReverseEngineeringAgent._pe_va_to_off(image_base, sections, va)
        if offset is None or offset + size > len(data):
            return None
        return data[offset : offset + size]

    @staticmethod
    def _pe_va_in_named_section(image_base: int, sections: List[Dict[str, int | str]], va: int, prefixes: tuple[str, ...]) -> bool:
        rva = va - image_base
        for section in sections:
            if not str(section["name"]).startswith(prefixes):
                continue
            start = int(section["vaddr"])
            size = max(int(section["vsize"]), int(section["raw_size"]))
            if start <= rva < start + size:
                return True
        return False

    @staticmethod
    def _find_pe_lea_to_va(data: bytes, image_base: int, text: Dict[str, int | str], target_va: int) -> Optional[int]:
        valid_modrm = {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}
        raw = int(text["raw"])
        text_data = data[raw : raw + int(text["raw_size"])]
        text_va = image_base + int(text["vaddr"])
        for idx in range(1, len(text_data) - 6):
            if text_data[idx] != 0x8D:
                continue
            rex = text_data[idx - 1]
            if (rex & 0xF0) != 0x40 or (rex & 0x08) == 0 or text_data[idx + 1] not in valid_modrm:
                continue
            disp = struct.unpack_from("<i", text_data, idx + 2)[0]
            instr_va = text_va + idx - 1
            if instr_va + 7 + disp == target_va:
                return instr_va
        return None

    @staticmethod
    def _match_pe_rip_relative_load(
        data: bytes,
        image_base: int,
        sections: List[Dict[str, int | str]],
        text_data: bytes,
        text_va: int,
        offset: int,
        allowed_prefixes: Optional[tuple[str, ...]] = None,
    ) -> Optional[tuple[int, int, int]]:
        valid_modrm = {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}
        if offset + 7 > len(text_data):
            return None
        rex, opcode, modrm = text_data[offset], text_data[offset + 1], text_data[offset + 2]
        if (rex & 0xF0) != 0x40 or (rex & 0x08) == 0 or opcode not in (0x8B, 0x8D) or modrm not in valid_modrm:
            return None
        disp = struct.unpack_from("<i", text_data, offset + 3)[0]
        instr_va = text_va + offset
        target_va = instr_va + 7 + disp
        final_va = target_va
        if opcode == 0x8B:
            pointer = ReverseEngineeringAgent._pe_read_va(data, image_base, sections, target_va, 8)
            if not pointer:
                return None
            final_va = struct.unpack("<Q", pointer)[0]
        if allowed_prefixes and not ReverseEngineeringAgent._pe_va_in_named_section(image_base, sections, final_va, allowed_prefixes):
            return None
        if not ReverseEngineeringAgent._pe_read_va(data, image_base, sections, final_va, 32):
            return None
        return instr_va, target_va, final_va

    @staticmethod
    def _find_godot_key_blob_near(
        data: bytes,
        image_base: int,
        sections: List[Dict[str, int | str]],
        text: Dict[str, int | str],
        lea_va: int,
    ) -> Optional[int]:
        raw = int(text["raw"])
        text_data = data[raw : raw + int(text["raw_size"])]
        text_va = image_base + int(text["vaddr"])
        lea_offset = ReverseEngineeringAgent._pe_va_to_off(image_base, sections, lea_va)
        if lea_offset is None:
            return None
        lea_index = lea_offset - raw
        start = max(0, lea_index - 0x4000)
        end = min(len(text_data), lea_index + 0x4000)

        for idx in range(start, end - 5):
            if text_data[idx : idx + 5] != b"\xBA\x20\x00\x00\x00":
                continue
            for inner in range(idx + 5, min(idx + 0x300, len(text_data) - 7)):
                match = ReverseEngineeringAgent._match_pe_rip_relative_load(
                    data, image_base, sections, text_data, text_va, inner, (".data",)
                )
                if match:
                    return match[2]

        best: Optional[tuple[int, int]] = None
        for idx in range(start, end - 7):
            match = ReverseEngineeringAgent._match_pe_rip_relative_load(
                data, image_base, sections, text_data, text_va, idx, None
            )
            if not match:
                continue
            distance = abs(idx - lea_index)
            if best is None or distance < best[0]:
                best = (distance, match[2])
        return best[1] if best else None

    # ------------------------------------------------------------------
    # Strategy 1: encryptor reversal
    # ------------------------------------------------------------------

    def _try_encryptor_reversal(
        self,
        binary: str,
        enc_file: str,
        challenge: Dict[str, Any],
        steps: List[str],
    ) -> Optional[Dict[str, Any]]:
        steps.append(f"Detected encryptor binary ({os.path.basename(binary)}) + encrypted file ({os.path.basename(enc_file)})")

        raw = open(enc_file, "rb").read()
        if len(raw) < 5:
            steps.append("Encrypted file too small to analyse")
            return None

        # Inspect binary for srand/rand/time usage
        try:
            sym_out = subprocess.run(
                ["strings", "-n", "4", binary], capture_output=True, timeout=10
            ).stdout.decode("utf-8", errors="replace")
        except Exception:
            sym_out = ""

        uses_srand = "srand" in sym_out
        uses_time = "time" in sym_out
        uses_rand = "rand" in sym_out
        steps.append(
            f"Binary imports: srand={'yes' if uses_srand else 'no'}, "
            f"rand={'yes' if uses_rand else 'no'}, "
            f"time={'yes' if uses_time else 'no'}"
        )

        # --- Pattern: seed prepended to encrypted file (4-byte LE uint32) ---
        if uses_srand and uses_rand:
            seed_le = struct.unpack("<I", raw[:4])[0]
            enc_data = raw[4:]
            steps.append(f"Seed from first 4 bytes of encrypted file: {seed_le} (0x{seed_le:08x})")

            # Try XOR+ROL (the simpleencryptor pattern)
            flag = self._decrypt_xor_rol(seed_le, enc_data, steps)
            if flag:
                return self._result(challenge, "solved", steps, flag=flag)

            # Try plain XOR (simpler variant)
            flag = self._decrypt_xor_only(seed_le, enc_data, steps)
            if flag:
                return self._result(challenge, "solved", steps, flag=flag)

        # --- Fallback: brute-force seed from file mtime ---
        if uses_srand and uses_rand and uses_time:
            steps.append("Brute-forcing seed from file mtime ± 120 seconds...")
            mtime = int(os.stat(enc_file).st_mtime)
            enc_data = raw  # treat whole file as ciphertext if seed isn't prepended

            for seed in range(mtime - 120, mtime + 121):
                flag = self._decrypt_xor_rol(seed, enc_data, steps=[])
                if flag:
                    steps.append(f"Seed found via mtime brute-force: {seed}")
                    steps.append(f"Flag: {flag}")
                    return self._result(challenge, "solved", steps, flag=flag)

        return None

    def _decrypt_xor_rol(self, seed: int, data: bytes, steps: List[str]) -> Optional[str]:
        """Reverse XOR+ROL encryption (glibc rand, 2 rand() calls per byte)."""
        try:
            state, fptr, rptr = _glibc_srand(seed)
            out = bytearray(len(data))
            for i, b in enumerate(data):
                r1, fptr, rptr = _glibc_rand(state, fptr, rptr)
                r2, fptr, rptr = _glibc_rand(state, fptr, rptr)
                k1 = r1 & 0xFF
                k2 = r2 & 7
                out[i] = _ror8(b, k2) ^ k1
            plaintext = out.decode("utf-8", errors="replace")
            flag = find_first_flag(plaintext)
            if flag:
                steps.append(f"XOR+ROL decryption succeeded: {flag}")
            return flag
        except Exception as exc:
            logger.debug("XOR+ROL decryption failed: %s", exc)
            return None

    def _decrypt_xor_only(self, seed: int, data: bytes, steps: List[str]) -> Optional[str]:
        """Reverse plain XOR encryption (glibc rand, 1 rand() call per byte)."""
        try:
            state, fptr, rptr = _glibc_srand(seed)
            out = bytearray(len(data))
            for i, b in enumerate(data):
                r, fptr, rptr = _glibc_rand(state, fptr, rptr)
                out[i] = b ^ (r & 0xFF)
            plaintext = out.decode("utf-8", errors="replace")
            flag = find_first_flag(plaintext)
            if flag:
                steps.append(f"XOR-only decryption succeeded: {flag}")
            return flag
        except Exception as exc:
            logger.debug("XOR-only decryption failed: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Strategy 4: .NET assembly — encrypted embedded resource
    # ------------------------------------------------------------------

    _ILSPYCMD_PATHS = [
        "ilspycmd",
        os.path.expanduser("~/.dotnet/tools/ilspycmd"),
    ]

    def _find_ilspycmd(self) -> Optional[str]:
        for p in self._ILSPYCMD_PATHS:
            if shutil.which(p) or os.path.isfile(p):
                return p
        return None

    def _try_dotnet_resource(
        self,
        binary: str,
        challenge: Dict[str, Any],
        steps: List[str],
    ) -> Optional[Dict[str, Any]]:
        """
        .NET assemblies can embed an AES-CBC encrypted resource that stores all
        strings (BinaryReader format, UTF-16LE).  Pattern:
          - PE is a Mono/.NET assembly (check strings for 'v4.0.30319' or '#Strings')
          - Resource blob: [32B key][16B IV][ciphertext]
          - Strings format: 7-bit varint length + UTF-16LE data
        Extracts every string and searches for a valid flag.
        """
        try:
            hdr = subprocess.run(
                ["strings", "-n", "6", binary],
                capture_output=True, timeout=10,
            ).stdout.decode("utf-8", errors="replace")
        except Exception:
            return None

        # Quick fingerprint: .NET metadata magic
        if not any(s in hdr for s in ("v4.0.30319", "#Strings", "mscorlib", "BSJB")):
            return None

        steps.append(f"Detected .NET assembly: {os.path.basename(binary)}")

        # Parse PE to find the managed resource blob
        flag = self._extract_dotnet_flag(binary, steps)
        if flag:
            return self._result(challenge, "solved", steps, flag=flag)

        # Fallback: decompile with ilspycmd and scan decompiled source for flags
        ilspy = self._find_ilspycmd()
        if not ilspy:
            steps.append("ilspycmd not found; install with: dotnet tool install -g ilspycmd")
            return None

        dotnet_root = os.environ.get("DOTNET_ROOT", "/opt/homebrew/opt/dotnet/libexec")
        env = {**os.environ, "DOTNET_ROOT": dotnet_root}
        try:
            r = subprocess.run(
                [ilspy, binary],
                capture_output=True, text=True, timeout=30, env=env,
            )
            src = r.stdout
        except Exception as exc:
            steps.append(f"ilspycmd failed: {exc}")
            return None

        flag = find_first_flag(src)
        if flag:
            steps.append(f"Flag found in decompiled source: {flag}")
            return self._result(challenge, "solved", steps, flag=flag)

        steps.append("No flag found in decompiled .NET source")
        return None

    def _extract_dotnet_flag(self, binary: str, steps: List[str]) -> Optional[str]:
        """
        Directly parse the PE/CLI structure to extract and decrypt the managed
        resource, then read all BinaryReader strings looking for a flag.
        """
        try:
            data = open(binary, "rb").read()
        except Exception:
            return None

        # Locate section table
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        opt_off = pe_off + 24
        magic = struct.unpack_from("<H", data, opt_off)[0]
        opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
        section_count = struct.unpack_from("<H", data, pe_off + 6)[0]
        sect_off = opt_off + opt_size

        sections = []
        for i in range(section_count):
            base = sect_off + i * 40
            vaddr   = struct.unpack_from("<I", data, base + 12)[0]
            rawsize = struct.unpack_from("<I", data, base + 16)[0]
            rawoff  = struct.unpack_from("<I", data, base + 20)[0]
            sections.append((vaddr, rawoff, rawsize))

        def rva2off(rva: int) -> Optional[int]:
            for vaddr, rawoff, rawsize in sections:
                if vaddr <= rva < vaddr + rawsize * 4:
                    return rawoff + (rva - vaddr)
            return None

        # CLI header: data directory 14 (PE32: opt+208, PE32+: opt+224)
        clr_rva_off = opt_off + (208 if magic == 0x10B else 224)
        clr_rva = struct.unpack_from("<I", data, clr_rva_off)[0]
        cli_off = rva2off(clr_rva)
        if not cli_off:
            return None

        res_rva  = struct.unpack_from("<I", data, cli_off + 24)[0]
        res_size = struct.unpack_from("<I", data, cli_off + 28)[0]
        res_off  = rva2off(res_rva)
        if not res_off or res_size < 64:
            return None

        # Resource blob: 4-byte length prefix then [key][IV][ciphertext]
        blob_len = struct.unpack_from("<I", data, res_off)[0]
        blob = data[res_off + 4 : res_off + 4 + blob_len]
        if len(blob) < 64:
            return None

        # Try AES-256-CBC (32-byte key + 16-byte IV)
        try:
            from Crypto.Cipher import AES
            key, iv, ct = blob[:32], blob[32:48], blob[48:]
            pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
        except ImportError:
            steps.append("pycryptodome not installed; cannot decrypt .NET resource")
            return None
        except Exception:
            return None

        steps.append("Decrypted .NET embedded resource (AES-256-CBC)")

        # Read all BinaryReader strings (7-bit varint length + UTF-16LE)
        buf = io.BytesIO(pt)
        strings: List[str] = []
        for _ in range(64):
            try:
                shift = length = 0
                while True:
                    b = buf.read(1)
                    if not b:
                        break
                    bv = b[0]
                    length |= (bv & 0x7F) << shift
                    if not (bv & 0x80):
                        break
                    shift += 7
                else:
                    continue
                if length > 4096:
                    break
                raw = buf.read(length)
                strings.append(raw.decode("utf-16-le", errors="replace"))
            except Exception:
                break

        # Check each string individually, then all pairs, then all triples.
        # Collect ALL candidates and return the shortest — CTF flag bodies are
        # rarely more than 50 characters; the short one is almost always correct.
        candidates: List[str] = []
        n = len(strings)

        for s in strings:
            flag = find_first_flag(s)
            if flag:
                candidates.append(flag)

        for i in range(n):
            for j in range(n):
                if i != j:
                    flag = find_first_flag(strings[i] + strings[j])
                    if flag:
                        candidates.append(flag)

        for i in range(n):
            for j in range(n):
                for k in range(n):
                    if len({i, j, k}) == 3:
                        flag = find_first_flag(strings[i] + strings[j] + strings[k])
                        if flag:
                            candidates.append(flag)

        if candidates:
            best = min(candidates, key=len)
            steps.append(f".NET resource flag (shortest of {len(candidates)} candidates): {best}")
            return best

        return None

    # ------------------------------------------------------------------
    # Pre-processing: UPX unpacking
    # ------------------------------------------------------------------

    def _unpack_upx(self, file_path: str, steps: List[str]) -> str:
        """If file_path is a UPX-packed ELF or PE, unpack to /tmp and return new path."""
        if not is_native_binary(file_path):
            return file_path
        try:
            raw = subprocess.run(
                ["strings", "-n", "4", file_path],
                capture_output=True, timeout=10,
            ).stdout.decode("utf-8", errors="replace")
        except Exception:
            return file_path

        if "UPX" not in raw:
            return file_path

        import tempfile
        out = os.path.join(tempfile.gettempdir(), f"upx_unpacked_{os.path.basename(file_path)}")
        try:
            r = subprocess.run(
                ["upx", "-d", file_path, "-o", out],
                capture_output=True, timeout=30,
            )
            if r.returncode == 0 and os.path.exists(out):
                steps.append(f"UPX-packed binary detected; unpacked to {out}")
                return out
            steps.append(f"upx -d failed: {r.stderr.decode(errors='replace')[:200]}")
        except FileNotFoundError:
            steps.append("upx not installed; analysing packed binary directly")
        except Exception as exc:
            steps.append(f"UPX unpack error: {exc}")
        return file_path

    # ------------------------------------------------------------------
    # Strategy 5: AES-NI self-decrypting shellcode (Windows PE)
    # ------------------------------------------------------------------

    @staticmethod
    def _aeskeygenassist(src: List[int], rcon: int) -> List[int]:
        """
        Simulate Intel AESKEYGENASSIST xmm1, xmm2, imm8.

        Intel SDM layout (little-endian byte order in XMM register):
          X1 = src[4:8]   (bits [63:32])
          X3 = src[12:16] (bits [127:96])
          DEST[31:0]   (bytes 0-3)  = SubWord(X1)
          DEST[63:32]  (bytes 4-7)  = RotWord(SubWord(X1)) XOR {rcon,0,0,0}
          DEST[95:64]  (bytes 8-11) = SubWord(X3)
          DEST[127:96] (bytes 12-15)= RotWord(SubWord(X3)) XOR {rcon,0,0,0}
        """
        def _subword(w: List[int]) -> List[int]:
            return [_AES_SBOX[b] for b in w]

        def _rotword(w: List[int]) -> List[int]:
            return [w[1], w[2], w[3], w[0]]

        X1, X3 = list(src[4:8]), list(src[12:16])
        sw1, sw3 = _subword(X1), _subword(X3)
        rw1, rw3 = _rotword(sw1), _rotword(sw3)
        rw1[0] ^= rcon
        rw3[0] ^= rcon
        return sw1 + rw1 + sw3 + rw3

    @staticmethod
    def _aesdeclast(state: List[int], rk: List[int]) -> List[int]:
        """
        Simulate Intel AESDECLAST xmm1, xmm2: InvShiftRows → InvSubBytes → XOR.
        """
        s = list(state)
        # InvShiftRows
        s[1], s[5], s[9],  s[13] = s[13], s[1],  s[5],  s[9]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2],  s[6]
        s[3], s[7], s[11], s[15] = s[7],  s[11], s[15], s[3]
        # InvSubBytes
        s = [_AES_INV_SBOX[b] for b in s]
        # AddRoundKey
        return [s[i] ^ rk[i] for i in range(16)]

    @staticmethod
    def _aes_ni_decrypt_block(block: List[int], key: List[int]) -> List[int]:
        """
        Decrypt one 16-byte block using the AES-NI 1-round cipher:
          rk0 = AESKEYGENASSIST(key, 0x00)
          rk1 = AESKEYGENASSIST(key, 0x10)
          tmp = block XOR rk1
          result = AESDECLAST(tmp, rk0)
        """
        rk0 = ReverseEngineeringAgent._aeskeygenassist(key, 0x00)
        rk1 = ReverseEngineeringAgent._aeskeygenassist(key, 0x10)
        tmp = [block[j] ^ rk1[j] for j in range(16)]
        return ReverseEngineeringAgent._aesdeclast(tmp, rk0)

    @staticmethod
    def _parse_pe_sections(data: bytes) -> List[tuple]:
        """
        Parse PE section table.
        Returns list of (name, vaddr, rawoff, rawsz, vsize) tuples.
        """
        try:
            pe_off = struct.unpack_from("<I", data, 0x3C)[0]
            num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
            opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
            sect_base = pe_off + 24 + opt_size
            sections = []
            for i in range(num_sections):
                s = sect_base + i * 40
                name   = data[s:s+8].rstrip(b"\x00").decode("ascii", errors="replace")
                vsize  = struct.unpack_from("<I", data, s + 8)[0]
                vaddr  = struct.unpack_from("<I", data, s + 12)[0]
                rawsz  = struct.unpack_from("<I", data, s + 16)[0]
                rawoff = struct.unpack_from("<I", data, s + 20)[0]
                sections.append((name, vaddr, rawoff, rawsz, vsize))
            return sections
        except Exception:
            return []

    @staticmethod
    def _pe_image_base(data: bytes) -> int:
        """Read the preferred load address from the PE optional header."""
        try:
            pe_off = struct.unpack_from("<I", data, 0x3C)[0]
            magic  = struct.unpack_from("<H", data, pe_off + 24)[0]
            if magic == 0x10B:   # PE32
                return struct.unpack_from("<I", data, pe_off + 52)[0]
            return struct.unpack_from("<Q", data, pe_off + 48)[0]  # PE32+
        except Exception:
            return 0x140000000

    def _find_aes_ni_blobs(
        self, objout: str, image_base: int
    ) -> List[tuple]:
        """
        Scan objdump output for (rva, size) pairs corresponding to encrypted blobs.

        Recognises the pattern emitted by MSVC for AES-NI shellcode loaders:
          mov edx, <SIZE>
          lea rcx, [rip + N]  # <ADDR>
          call <decrypt_func>
        """
        blobs: List[tuple] = []
        lines = objout.splitlines()
        for i, line in enumerate(lines):
            m_size = re.search(r'\bmov\s+edx,\s*(0x[0-9a-f]+|\d+)', line)
            if not m_size:
                continue
            size = int(m_size.group(1), 0)
            if size < 16 or size > 0x8000 or (size % 16) != 0:
                continue
            # Look for `lea rcx, [...] # ADDR` within the next 4 lines
            for j in range(i + 1, min(i + 5, len(lines))):
                m_addr = re.search(r'#\s*(0x[0-9a-f]+)', lines[j])
                if m_addr and "lea" in lines[j] and "rcx" in lines[j]:
                    addr = int(m_addr.group(1), 16)
                    rva  = addr - image_base
                    if 0 < rva < 0x200000:
                        blobs.append((rva, size))
                    break
        # deduplicate, preserving order
        seen: set = set()
        unique = []
        for item in blobs:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        return unique

    @staticmethod
    def _extract_aes_ni_char_checks(shellcode: bytes, md) -> Dict[int, int]:
        """
        Disassemble decrypted shellcode and extract {flag_position: expected_char}.

        The shellcode performs per-character validation with this pattern:
          imul rcx, rcx, <POSITION>   ; flag index
          movsx eax, byte ptr [...]   ; load argv[1][pos]
          cmp eax, <CHAR>             ; expected character
        """
        checks: Dict[int, int] = {}
        insns = list(md.disasm(shellcode, 0))
        for idx, insn in enumerate(insns):
            if insn.mnemonic != "imul" or "rcx, rcx," not in insn.op_str:
                continue
            op = insn.op_str.split(",")[-1].strip()
            try:
                pos = int(op, 16) if op.startswith("0x") else int(op)
            except ValueError:
                continue
            for ni in insns[idx + 1 : idx + 10]:
                if ni.mnemonic == "cmp" and ni.op_str.startswith("eax,"):
                    char_str = ni.op_str.split(",")[1].strip()
                    try:
                        char_val = int(char_str, 16) if char_str.startswith("0x") else int(char_str)
                        checks[pos] = char_val
                    except ValueError:
                        pass
                    break
        return checks

    def _try_aes_ni_shellcode(
        self,
        binary: str,
        challenge: Dict[str, Any],
        steps: List[str],
    ) -> Optional[Dict[str, Any]]:
        """
        Reverse AES-NI self-decrypting shellcode PE challenges.

        Pattern (MSVC/Windows):
        - Encrypted code blobs live in .data, referenced by RVA from .text.
        - A loader function allocates RWX memory, decrypts each blob using a
          1-round AES cipher (key = [block_index]*16), then executes it.
        - Each shellcode stub calls putchar() per character (usage/response
          strings) or compares argv[1] character-by-character against expected
          values, ORing a running failure flag.
        Detection: AESKEYGENASSIST + AESDECLAST in the binary disassembly.
        """
        try:
            objout = subprocess.run(
                ["objdump", "-d", "-M", "intel", binary],
                capture_output=True, text=True, timeout=30,
            ).stdout
        except Exception:
            return None

        objout_lower = objout.lower()
        if "aesdeclast" not in objout_lower or "aeskeygenassist" not in objout_lower:
            return None

        steps.append(
            f"AES-NI self-decrypting shellcode detected in {os.path.basename(binary)}"
        )

        try:
            data = open(binary, "rb").read()
        except Exception:
            return None

        image_base = self._pe_image_base(data)
        sections   = self._parse_pe_sections(data)

        def rva2off(rva: int) -> Optional[int]:
            for _name, vaddr, rawoff, rawsz, vsize in sections:
                if vaddr <= rva < vaddr + max(rawsz, vsize):
                    return rawoff + (rva - vaddr)
            return None

        blobs = self._find_aes_ni_blobs(objout, image_base)
        if not blobs:
            steps.append("Could not locate encrypted blob RVAs from disassembly")
            return None

        steps.append(f"Found {len(blobs)} encrypted blob(s): {blobs}")

        try:
            import capstone  # type: ignore
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        except ImportError:
            steps.append("capstone not installed; cannot disassemble shellcodes")
            return None

        all_checks: Dict[int, int] = {}
        for rva, size in blobs:
            fo = rva2off(rva)
            if fo is None or fo + size > len(data):
                continue
            blob = data[fo : fo + size]
            decrypted = bytearray()
            for bi in range(size // 16):
                block = list(blob[bi * 16 : (bi + 1) * 16])
                key   = [bi & 0xFF] * 16
                decrypted.extend(self._aes_ni_decrypt_block(block, key))
            checks = self._extract_aes_ni_char_checks(bytes(decrypted), md)
            all_checks.update(checks)

        if len(all_checks) < 4:
            steps.append(f"Too few character checks found ({len(all_checks)}); skipping")
            return None

        max_pos   = max(all_checks.keys())
        flag_chars = [chr(all_checks.get(p, ord("?"))) for p in range(max_pos + 1)]
        candidate  = "".join(flag_chars)
        flag       = find_first_flag(candidate)
        if flag:
            steps.append(
                f"AES-NI shellcode: {len(all_checks)} checks → {flag}"
            )
            return self._result(challenge, "solved", steps, flag=flag)

        steps.append(f"Assembled candidate '{candidate}' — no valid flag pattern found")
        return None

    # ------------------------------------------------------------------
    # Strategy 3: numeric-encoded flag  (char_code × N stored as ints)
    # ------------------------------------------------------------------

    def _try_numeric_encoding(
        self,
        binary: str,
        challenge: Dict[str, Any],
        steps: List[str],
    ) -> Optional[Dict[str, Any]]:
        """
        Detect flags encoded as space-separated integers where each value equals
        ord(char) * N for some constant multiplier N (e.g. N=16 for a left-shift-
        by-4 encoding).  Searches all long integer sequences in the binary's
        strings output, finds a GCD-based multiplier, and checks whether the
        decoded bytes form a valid flag.
        """
        try:
            raw = subprocess.run(
                ["strings", "-n", "20", binary],
                capture_output=True, timeout=15,
            ).stdout.decode("utf-8", errors="replace")
        except Exception:
            return None

        import math

        for line in raw.splitlines():
            parts = line.split()
            if len(parts) < 8:
                continue
            try:
                vals = [int(p) for p in parts]
            except ValueError:
                continue
            if any(v <= 0 or v > 0x7F * 256 for v in vals):
                continue

            gcd = vals[0]
            for v in vals[1:]:
                gcd = math.gcd(gcd, v)
            if gcd < 1:
                continue

            for multiplier in (gcd, gcd * 2, gcd // 2 if gcd % 2 == 0 else None):
                if not multiplier or multiplier < 1:
                    continue
                try:
                    chars = [v // multiplier for v in vals]
                except ZeroDivisionError:
                    continue
                if not all(0x20 <= c <= 0x7E for c in chars):
                    continue
                candidate = "".join(chr(c) for c in chars)
                flag = find_first_flag(candidate)
                if flag:
                    steps.append(
                        f"Numeric encoding detected (multiplier={multiplier}): {candidate}"
                    )
                    return self._result(challenge, "solved", steps, flag=flag)

        return None

    # ------------------------------------------------------------------
    # Strategy 4: substitution-table bytecode VM verifier
    # ------------------------------------------------------------------

    def _try_substitution_table_vm(
        self,
        binary: str,
        challenge: Dict[str, Any],
        steps: List[str],
    ) -> Optional[Dict[str, Any]]:
        steps.append("Checking for substitution-table bytecode VM verifier.")
        try:
            sections = self._parse_elf_sections(Path(binary).read_bytes())
        except Exception as exc:
            steps.append(f"ELF section parsing failed: {exc}")
            return None

        data_section = sections.get(".data")
        rodata_section = sections.get(".rodata")
        if not data_section or not rodata_section:
            return None

        rodata = rodata_section["data"]
        table_offsets = [0x78]
        table_offsets.extend(
            idx for idx in range(0, max(0, len(rodata) - 256))
            if rodata[idx + 256:idx + 263] == b"yes\nno\n"
        )

        seen_offsets: set[int] = set()
        for table_offset in table_offsets:
            if table_offset in seen_offsets:
                continue
            seen_offsets.add(table_offset)
            table = rodata[table_offset:table_offset + 256]
            if len(table) != 256:
                continue

            candidate = self._recover_substitution_table_vm_flag(data_section["data"], table)
            if not candidate:
                continue

            steps.append(f"Recovered substitution-table VM candidate: {candidate}")
            submission_candidate = self._normalize_uscg_submission_candidate(candidate)
            artifacts: Dict[str, Any] = {}
            if submission_candidate != candidate:
                steps.append(f"VM accepted input: {candidate}")
                steps.append(f"Normalized US Cyber Games submission candidate: {submission_candidate}")
                artifacts["vm_accepted_input"] = candidate
                artifacts["submission_candidates"] = self._uscg_submission_candidates(candidate)

            flag = find_first_flag(submission_candidate)
            if flag:
                return self._result(
                    challenge,
                    "solved",
                    steps,
                    flag=flag,
                    artifacts=artifacts or None,
                )

        return None

    @staticmethod
    def _normalize_uscg_submission_candidate(candidate: str) -> str:
        """Normalize legacy USCG crackme prefixes to a likely BGR submission prefix."""
        if candidate.startswith("SVIUSCG{"):
            return "SVBRG{" + candidate[len("SVIUSCG{"):]
        return candidate

    @staticmethod
    def _uscg_submission_candidates(candidate: str) -> List[str]:
        if not candidate.startswith("SVIUSCG{"):
            return [candidate]
        body = candidate[len("SVIUSCG{"):]
        return [
            candidate,
            "SVBRG{" + body,
            "SVIBGR{" + body,
        ]

    @staticmethod
    def _parse_elf_sections(data: bytes) -> Dict[str, Dict[str, Any]]:
        """Return ELF64 little-endian sections keyed by name."""
        if len(data) < 0x40 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            return {}

        e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
        e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
        e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
        e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
        if not e_shoff or not e_shentsize or e_shstrndx >= e_shnum:
            return {}

        raw_sections = []
        for index in range(e_shnum):
            offset = e_shoff + index * e_shentsize
            if offset + 64 > len(data):
                return {}
            raw_sections.append(struct.unpack_from("<IIQQQQIIQQ", data, offset))

        shstr = raw_sections[e_shstrndx]
        shstr_data = data[shstr[4]:shstr[4] + shstr[5]]
        sections: Dict[str, Dict[str, Any]] = {}
        for section in raw_sections:
            name_offset = section[0]
            end = shstr_data.find(b"\0", name_offset)
            if end < 0:
                continue
            name = shstr_data[name_offset:end].decode("utf-8", errors="replace")
            file_offset = section[4]
            size = section[5]
            sections[name] = {
                "addr": section[3],
                "offset": file_offset,
                "size": size,
                "data": data[file_offset:file_offset + size],
            }
        return sections

    @staticmethod
    def _recover_substitution_table_vm_flag(program: bytes, table: bytes) -> Optional[str]:
        """Solve the small substitution-table VM used by stripped crackmes."""
        if len(program) < 16 or len(table) != 256:
            return None

        try:
            import z3  # type: ignore
        except Exception:
            return None

        class Expr:
            def __init__(self, fn, deps: set[int]):
                self.fn = fn
                self.deps = set(deps)

        def expr_var(index: int) -> Expr:
            return Expr(lambda values, index=index: values[index], {index})

        def expr_op(current: Expr, fn) -> Expr:
            return Expr(
                lambda values, current=current, fn=fn: fn(current.fn(values)) & 0xFF,
                set(current.deps),
            )

        concrete_program = bytearray(program)
        assigned: List[Optional[int]] = [None] * 128
        pc = 0
        r11 = 0
        r12 = 0
        expr = Expr(lambda values: 0, set())
        printable = list(range(0x20, 0x7F)) + [0x0A, 0x00]

        while pc < len(concrete_program):
            opcode_pc = pc
            opcode = concrete_program[pc]
            pc += 1
            if opcode == 0:
                return None
            if opcode == 1:
                r11 = concrete_program[pc]
                pc += 1
            elif opcode == 2:
                expr = expr_var(r11)
            elif opcode == 3:
                value = concrete_program[pc]
                pc += 1
                expr = expr_op(expr, lambda item, value=value: item ^ value)
            elif opcode == 4:
                value = concrete_program[pc]
                pc += 1
                expr = expr_op(expr, lambda item, value=value: item + value)
            elif opcode == 5:
                expected = concrete_program[pc]
                pc += 1
                unresolved = [idx for idx in expr.deps if assigned[idx] is None]
                if len(unresolved) > 2:
                    pc = opcode_pc
                    break
                matches = []
                for values in itertools.product(printable, repeat=len(unresolved)):
                    candidate = list(assigned)
                    for idx, value in zip(unresolved, values):
                        candidate[idx] = value
                    try:
                        if expr.fn(candidate) == expected:
                            matches.append(candidate)
                    except Exception:
                        continue
                if len(matches) != 1:
                    pc = opcode_pc
                    break
                assigned = matches[0]
            elif opcode == 6:
                r11 = concrete_program[pc]
                pc += 1
                if assigned[r11] is None:
                    assigned[r11] = 0x0A
                elif assigned[r11] not in {0x00, 0x0A}:
                    return None
            elif opcode == 7:
                return ReverseEngineeringAgent._bytes_to_flag_candidate(assigned)
            elif opcode == 8:
                expr = expr_op(expr, lambda item, r12=r12: item ^ r12)
            elif opcode == 9:
                if assigned[r11] is None:
                    return None
                r12 = table[(r12 ^ assigned[r11]) & 0xFF]
            elif opcode == 10:
                expr = expr_op(expr, lambda item, table=table: table[item])
            elif opcode == 11:
                if pc + 2 > len(concrete_program):
                    return None
                size = concrete_program[pc] | (concrete_program[pc + 1] << 8)
                pc += 2
                if pc + size > len(concrete_program):
                    return None
                for idx in range(size):
                    concrete_program[pc + idx] ^= r12
            elif opcode == 12:
                pc += 3
            elif opcode == 13:
                pc += 1
            elif opcode == 14:
                index = concrete_program[pc]
                pc += 1

                def mixed(values, current=expr, index=index, table=table):
                    item = current.fn(values)
                    shifted = (item << 1) & 0xFF
                    if item & 0x80:
                        shifted ^= 0x4B
                    return table[(shifted ^ item ^ values[index]) & 0xFF]

                expr = Expr(mixed, set(expr.deps) | {index})
            else:
                return None

        return ReverseEngineeringAgent._solve_substitution_vm_symbolically(
            bytearray(program),
            table,
            assigned,
        )

    @staticmethod
    def _solve_substitution_vm_symbolically(
        program: bytearray,
        table: bytes,
        assigned: List[Optional[int]],
    ) -> Optional[str]:
        try:
            import z3  # type: ignore
        except Exception:
            return None

        solver = z3.Solver()
        variables = [z3.BitVec(f"vm_input_{idx}", 8) for idx in range(128)]
        for idx, value in enumerate(assigned):
            if value is not None:
                solver.add(variables[idx] == value)

        allowed_bytes = list(range(0x20, 0x7F)) + [0x00, 0x0A]
        for idx in range(64):
            if assigned[idx] is None:
                solver.add(z3.Or([variables[idx] == value for value in allowed_bytes]))

        def table_lookup(item):
            out = z3.BitVecVal(table[255], 8)
            for idx in range(254, -1, -1):
                out = z3.If(item == idx, z3.BitVecVal(table[idx], 8), out)
            return out

        def mix(item, index: int):
            shifted = (item << 1) & 0xFF
            reduced = z3.If((item & 0x80) != 0, shifted ^ z3.BitVecVal(0x4B, 8), shifted)
            return table_lookup(reduced ^ item ^ variables[index])

        pc = 0
        r11 = 0
        r12 = 0
        expr = z3.BitVecVal(0, 8)
        while pc < len(program):
            opcode = program[pc]
            pc += 1
            if opcode == 0:
                return None
            if opcode == 1:
                r11 = program[pc]
                pc += 1
            elif opcode == 2:
                expr = variables[r11]
            elif opcode == 3:
                expr = expr ^ program[pc]
                pc += 1
            elif opcode == 4:
                expr = expr + program[pc]
                pc += 1
            elif opcode == 5:
                solver.add(expr == program[pc])
                pc += 1
            elif opcode == 6:
                r11 = program[pc]
                pc += 1
                solver.add(z3.Or(variables[r11] == 0, variables[r11] == 0x0A))
            elif opcode == 7:
                break
            elif opcode == 8:
                expr = expr ^ r12
            elif opcode == 9:
                if assigned[r11] is None:
                    return None
                r12 = table[(r12 ^ assigned[r11]) & 0xFF]
            elif opcode == 10:
                expr = table_lookup(expr)
            elif opcode == 11:
                size = program[pc] | (program[pc + 1] << 8)
                pc += 2
                if pc + size > len(program):
                    return None
                for idx in range(size):
                    program[pc + idx] ^= r12
            elif opcode == 12:
                left, right, expected = program[pc], program[pc + 1], program[pc + 2]
                pc += 3
                solver.add((variables[left] ^ variables[right]) == expected)
            elif opcode == 13:
                pc += 1
            elif opcode == 14:
                index = program[pc]
                pc += 1
                expr = mix(expr, index)
            else:
                return None

        if solver.check() != z3.sat:
            return None
        model = solver.model()
        solved = [
            model.eval(variables[idx], model_completion=True).as_long()
            for idx in range(128)
        ]
        return ReverseEngineeringAgent._bytes_to_flag_candidate(solved)

    @staticmethod
    def _bytes_to_flag_candidate(values: List[Optional[int]]) -> Optional[str]:
        raw = bytes((value or 0) & 0xFF for value in values)
        candidate = raw.split(b"\0", 1)[0].split(b"\n", 1)[0].decode("utf-8", errors="replace")
        flag = find_first_flag(candidate)
        return flag or None

    # ------------------------------------------------------------------
    # Strategy 5: indexed XOR/add phrase verifier
    # ------------------------------------------------------------------

    def _try_indexed_xor_phrase(
        self,
        binary: str,
        challenge: Dict[str, Any],
        steps: List[str],
    ) -> Optional[Dict[str, Any]]:
        steps.append("Checking for indexed XOR phrase verifier.")
        try:
            disasm = subprocess.run(
                ["objdump", "-d", binary],
                capture_output=True, text=True, timeout=15,
            ).stdout
            rodata = subprocess.run(
                ["objdump", "-s", "-j", ".rodata", binary],
                capture_output=True, text=True, timeout=15,
            ).stdout
        except Exception as exc:
            steps.append(f"Indexed-XOR analysis failed: {exc}")
            return None

        candidate = self._recover_indexed_xor_phrase_from_objdump(disasm, rodata)
        if not candidate:
            return None

        steps.append(f"Recovered indexed-XOR phrase candidate: {candidate}")
        flag = find_first_flag(candidate)
        if flag:
            return self._result(challenge, "solved", steps, flag=flag)
        return None

    @staticmethod
    def _recover_indexed_xor_phrase_from_objdump(disasm: str, rodata: str) -> Optional[str]:
        """
        Recover flags from verifier loops that compare each input byte against a
        .rodata table after applying a transform like `(input[i] ^ K) + i`.
        """
        rodata_bytes = ReverseEngineeringAgent._parse_objdump_bytes(rodata)
        if not rodata_bytes:
            return None

        lengths = ReverseEngineeringAgent._extract_indexed_xor_lengths(disasm)
        xor_consts = ReverseEngineeringAgent._extract_indexed_xor_consts(disasm)
        table_addrs = ReverseEngineeringAgent._extract_rip_relative_targets(disasm)
        if not lengths or not xor_consts or not table_addrs:
            return None

        for length in lengths:
            if length < 6 or length > 128:
                continue
            for xor_const in xor_consts:
                if xor_const < 0 or xor_const > 0xFF:
                    continue
                for table_addr in table_addrs:
                    encoded = [
                        rodata_bytes.get(table_addr + idx)
                        for idx in range(length)
                    ]
                    if any(value is None for value in encoded):
                        continue

                    for direction in (-1, 1):
                        decoded = []
                        for idx, value in enumerate(encoded):
                            assert value is not None
                            decoded.append(chr(((value + (direction * idx)) & 0xFF) ^ xor_const))
                        candidate = "".join(decoded)
                        if not all(ch.isprintable() for ch in candidate):
                            continue
                        flag = find_first_flag(candidate)
                        if flag:
                            return flag

        return None

    @staticmethod
    def _parse_objdump_bytes(objdump_output: str) -> Dict[int, int]:
        """Map virtual addresses to byte values from `objdump -s` output."""
        out: Dict[int, int] = {}
        for line in objdump_output.splitlines():
            parts = line.split()
            if not parts:
                continue
            try:
                addr = int(parts[0], 16)
            except ValueError:
                continue

            offset = 0
            for word in parts[1:]:
                if not re.fullmatch(r"[0-9A-Fa-f]+", word) or len(word) % 2:
                    break
                try:
                    chunk = bytes.fromhex(word)
                except ValueError:
                    break
                for byte in chunk:
                    out[addr + offset] = byte
                    offset += 1
        return out

    @staticmethod
    def _extract_indexed_xor_lengths(disasm: str) -> List[int]:
        lengths: List[int] = []

        # strlen-style checks commonly compare the returned length in a register.
        for match in re.finditer(r"\bcmp\w*\s+\$0x([0-9A-Fa-f]+),\s*%[a-z0-9]+", disasm):
            value = int(match.group(1), 16)
            if 6 <= value <= 128:
                lengths.append(value)

        # Loop bounds often compare i <= N, so the phrase length is N + 1.
        for match in re.finditer(r"\bcmp\w*\s+\$0x([0-9A-Fa-f]+),\s*[-0-9A-Fa-fx()%,]+", disasm):
            value = int(match.group(1), 16) + 1
            if 6 <= value <= 128:
                lengths.append(value)

        seen: set[int] = set()
        return [length for length in lengths if not (length in seen or seen.add(length))]

    @staticmethod
    def _extract_indexed_xor_consts(disasm: str) -> List[int]:
        consts: List[int] = []
        for match in re.finditer(r"\bxor\w*\s+\$0x([0-9A-Fa-f]+),", disasm):
            value = int(match.group(1), 16)
            if 0 <= value <= 0xFF:
                consts.append(value)
        seen: set[int] = set()
        return [const for const in consts if not (const in seen or seen.add(const))]

    @staticmethod
    def _extract_rip_relative_targets(disasm: str) -> List[int]:
        targets: List[int] = []
        for line in disasm.splitlines():
            if "lea" not in line and "mov" not in line:
                continue
            match = re.search(r"#\s*0x([0-9A-Fa-f]+)", line)
            if match:
                targets.append(int(match.group(1), 16))
        seen: set[int] = set()
        return [target for target in targets if not (target in seen or seen.add(target))]

    # ------------------------------------------------------------------
    # Strategy 2: crackme — password fragments in .rodata
    # ------------------------------------------------------------------

    _SKIP_STRINGS = frozenset({
        "GCC:", "GLIBC_", "libc.so", "ld-linux", ".dynamic",
        "crtstuff", "deregister_tm", "register_tm", "__do_global",
        "frame_dummy", "__init_array", "__FRAME_END__", "completed.",
        "_ITM_", "__gmon_start__", "__cxa_finalize", "__libc_start_main",
    })

    def _try_rodata_password(
        self,
        binary: str,
        challenge: Dict[str, Any],
        steps: List[str],
    ) -> Optional[Dict[str, Any]]:
        """
        Crackme pattern: binary compares argv[1] against strings stored in
        .rodata and prints HTB{<password>} on success.

        Dumps .rodata, extracts null-terminated strings, discards obvious
        non-password strings (library names, usage, format strings), then
        tries every non-empty concatenation order near the flag format string.
        """
        # Only attempt when binary imports a comparison function
        try:
            sym_out = subprocess.run(
                ["strings", "-n", "4", binary], capture_output=True, timeout=10
            ).stdout.decode("utf-8", errors="replace")
        except Exception:
            return None

        # PE binaries use _strcmp/_strncmp (decorated names) or same names via CRT
        has_cmp = any(s in sym_out for s in ("strncmp", "strcmp", "memcmp", "_strcmp", "_strncmp"))
        has_flag_fmt = any(
            pat in sym_out for pat in ("HTB{%s}", "> HTB{%", "CTF{%s}", "flag{%s}")
        )
        if not (has_cmp and has_flag_fmt):
            return None

        steps.append(f"Crackme pattern detected in {os.path.basename(binary)} (strncmp + HTB format string)")

        # ELF uses .rodata; PE uses .rdata
        section = ".rdata" if is_pe_binary(binary) else ".rodata"
        try:
            dump = subprocess.run(
                ["objdump", "-s", f"--section={section}", binary],
                capture_output=True, text=True, timeout=15,
            ).stdout
        except Exception as exc:
            steps.append(f"objdump {section} failed: {exc}")
            return None

        fragments = self._parse_rodata_strings(dump)
        steps.append(f".rodata strings: {fragments}")

        # Discard strings that are clearly not password material
        def _is_password_candidate(s: str) -> bool:
            if len(s) < 2:
                return False
            if any(skip in s for skip in self._SKIP_STRINGS):
                return False
            if s.startswith(("./", "/lib", "/proc", "<", ">")):
                return False
            if "%" in s:          # printf format strings
                return False
            if " " in s and len(s) > 8:   # usage strings like "./challenge <password>"
                return False
            return True

        candidates = [s for s in fragments if _is_password_candidate(s)]
        steps.append(f"Password fragment candidates: {candidates}")

        if not candidates:
            return None

        # Try the full concatenation (most common: all fragments in order)
        password = "".join(candidates)
        flag = f"HTB{{{password}}}"
        found = find_first_flag(flag)
        if found:
            steps.append(f"Flag assembled from .rodata fragments: {found}")
            return self._result(challenge, "solved", steps, flag=found)

        # Fallback: check if the concatenation itself already is a flag
        found = find_first_flag(password)
        if found:
            steps.append(f"Flag found directly in concatenated fragments: {found}")
            return self._result(challenge, "solved", steps, flag=found)

        return None

    @staticmethod
    def _parse_rodata_strings(objdump_output: str) -> List[str]:
        """
        Extract null-terminated printable strings from objdump hex dump output.
        Each line looks like:  <addr> <hex bytes> <ascii preview>
        We parse from the hex bytes and split on null bytes.
        """
        raw = bytearray()
        for line in objdump_output.splitlines():
            # Lines with data look like: " 2000 01000200 2e2f6368 ..."
            parts = line.split()
            if not parts or len(parts[0]) != 4:
                continue
            try:
                int(parts[0], 16)
            except ValueError:
                continue
            # Parts 1-4 are hex words (up to 4 bytes each)
            for word in parts[1:5]:
                try:
                    raw += bytes.fromhex(word)
                except ValueError:
                    break

        strings: List[str] = []
        buf: List[int] = []
        for b in raw:
            if b == 0:
                if buf:
                    try:
                        s = bytes(buf).decode("utf-8", errors="strict")
                        if s.isprintable():
                            strings.append(s)
                    except UnicodeDecodeError:
                        pass
                    buf = []
            elif 0x20 <= b <= 0x7E:
                buf.append(b)
            else:
                buf = []
        return strings

    # ------------------------------------------------------------------
    # Strategy 3: source code analysis
    # ------------------------------------------------------------------

    def _try_source_analysis(
        self,
        file_path: str,
        challenge: Dict[str, Any],
        steps: List[str],
    ) -> Optional[Dict[str, Any]]:
        steps.append(f"Analyzing source file: {file_path}")
        try:
            with open(file_path, "r", errors="replace") as f:
                content = f.read()
        except Exception as exc:
            steps.append(f"Could not read {file_path}: {exc}")
            return None

        steps.append("File read successfully.")

        target_sum_match = re.search(r"builder\s*==\s*(\d+)", content)
        length_match = re.search(r"len\(password\)\s*[=!]=\s*(\d+)", content)
        fixed_char_match = (
            re.search(r"password\[(\d+)\]\s*==\s*(\d+)", content)
            or re.search(r"ord\(password\[(\d+)\]\)\s*==\s*(\d+)", content)
        )

        if target_sum_match and length_match:
            target_sum = int(target_sum_match.group(1))
            target_len = int(length_match.group(1))
            steps.append(f"Constraints: sum={target_sum}, length={target_len}")

            fixed_idx = fixed_val = None
            if fixed_char_match:
                fixed_idx = int(fixed_char_match.group(1))
                fixed_val = int(fixed_char_match.group(2))
                steps.append(f"Fixed char: index {fixed_idx} = '{chr(fixed_val)}'")

            candidate = self._solve_sum_constraint(target_sum, target_len, fixed_idx, fixed_val)
            if candidate:
                steps.append(f"Candidate: {candidate!r}")
                res = self.python_tool.execute([file_path, candidate], timeout_s=5)
                if "correct" in res.stdout.lower():
                    steps.append("Verification succeeded.")
                    return self._result(challenge, "solved", steps, flag=candidate)
                steps.append(f"Verification failed: {res.stdout.strip()!r}")

        if not self.reasoner.is_available:
            steps.append("LLM not available for complex code analysis.")
            return None

        steps.append("Requesting LLM analysis...")
        try:
            result = self.reasoner._call_llm(
                f"Analyze this code and find a valid input:\n{content}"
            ).strip()
            if result:
                steps.append(f"LLM suggested: {result!r}")
                res = self.python_tool.execute([file_path, result], timeout_s=5)
                if "correct" in res.stdout.lower():
                    return self._result(challenge, "solved", steps, flag=result)
        except Exception as exc:
            steps.append(f"LLM error: {exc}")

        return None

    def _solve_sum_constraint(
        self, target_sum: int, length: int,
        fixed_idx: Optional[int], fixed_val: Optional[int],
    ) -> Optional[str]:
        slots = length - (1 if fixed_idx is not None else 0)
        remaining = target_sum - (fixed_val or 0)
        if slots <= 0:
            return None
        avg = remaining // slots
        remainder = remaining % slots
        password = [chr(avg)] * length
        if fixed_idx is not None:
            password[fixed_idx] = chr(fixed_val)
        for i in range(length):
            if i == fixed_idx:
                continue
            password[i] = chr(ord(password[i]) + remainder)
            break
        return "".join(password)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _result(
        challenge: Dict[str, Any],
        status: str,
        steps: List[str],
        flag: Optional[str] = None,
        artifacts: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "challenge_id": challenge.get("id"),
            "agent_id": "reverse_agent",
            "status": status,
            "steps": steps,
        }
        if flag is not None:
            out["flag"] = flag
        if artifacts:
            out["artifacts"] = artifacts
        return out

    def get_capabilities(self) -> List[str]:
        return self.capabilities

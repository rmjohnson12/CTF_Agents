"""
Reverse Engineering Specialist Agent

Handles both source-code analysis challenges (Python/C constraint solving)
and binary reversing challenges (ELF + encrypted-output patterns).
"""

import ctypes
import logging
import os
import re
import struct
import subprocess
from typing import Any, Dict, List, Optional

from agents.base_agent import BaseAgent, AgentType
from core.decision_engine.llm_reasoner import LLMReasoner
from core.utils.flag_utils import find_first_flag
from tools.common.elf_utils import is_elf_binary
from tools.common.python_tool import PythonTool

logger = logging.getLogger(__name__)

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
        ]

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        description = challenge.get("description", "").lower()
        files = challenge.get("files", [])
        tags = " ".join(challenge.get("tags", [])).lower()

        has_binary = any(is_elf_binary(f) for f in files)
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

        if not files:
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "failed",
                "flag": None,
                "steps": ["No files provided for analysis"],
            }

        binaries = [f for f in files if is_elf_binary(f)]
        enc_files = [f for f in files if f.endswith(".enc") or f.endswith(".encrypted")]
        source_files = [f for f in files if f.endswith((".py", ".c", ".cpp", ".js"))]

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

        # --- Strategy 3: source code constraint solving ---
        for file_path in source_files:
            result = self._try_source_analysis(file_path, challenge, steps)
            if result:
                return result

        # --- Strategy 3: strings + LLM on any remaining file ---
        for file_path in files:
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
                if self.reasoner.is_available and printable.strip():
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
            except Exception as exc:
                logger.debug("strings failed on %s: %s", file_path, exc)
                steps.append(f"strings error on {file_path}: {exc}")

        return self._result(challenge, "attempted", steps)

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

        has_cmp = any(s in sym_out for s in ("strncmp", "strcmp", "memcmp"))
        has_flag_fmt = any(
            pat in sym_out for pat in ("HTB{%s}", "> HTB{%", "CTF{%s}", "flag{%s}")
        )
        if not (has_cmp and has_flag_fmt):
            return None

        steps.append(f"Crackme pattern detected in {os.path.basename(binary)} (strncmp + HTB format string)")

        # Dump .rodata
        try:
            dump = subprocess.run(
                ["objdump", "-s", "--section=.rodata", binary],
                capture_output=True, text=True, timeout=15,
            ).stdout
        except Exception as exc:
            steps.append(f"objdump .rodata failed: {exc}")
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
    ) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "challenge_id": challenge.get("id"),
            "agent_id": "reverse_agent",
            "status": status,
            "steps": steps,
        }
        if flag is not None:
            out["flag"] = flag
        return out

    def get_capabilities(self) -> List[str]:
        return self.capabilities

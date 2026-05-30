"""
Reverse Engineering Specialist Agent

Handles both source-code analysis challenges (Python/C constraint solving)
and binary reversing challenges (ELF + encrypted-output patterns).
"""

import ctypes
import io
import logging
import os
import re
import shutil
import struct
import subprocess
from typing import Any, Dict, List, Optional

from agents.base_agent import BaseAgent, AgentType
from core.decision_engine.llm_reasoner import LLMReasoner
from core.utils.flag_utils import find_first_flag
from tools.common.elf_utils import is_elf_binary, is_native_binary, is_pe_binary
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
        source_files = [f for f in effective_files if f.endswith((".py", ".c", ".cpp", ".js"))]

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

        # --- Strategy 4: .NET assembly with encrypted embedded resource ---
        for binary in binaries:
            if is_pe_binary(binary):
                result = self._try_dotnet_resource(binary, challenge, steps)
                if result:
                    return result

        # --- Strategy 5: source code constraint solving ---
        for file_path in source_files:
            result = self._try_source_analysis(file_path, challenge, steps)
            if result:
                return result

        # --- Strategy 5: strings + LLM on any remaining file ---
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

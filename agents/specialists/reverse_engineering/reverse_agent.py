"""
Reverse Engineering Specialist Agent

Handles both source-code analysis challenges (Python/C constraint solving)
and binary reversing challenges (ELF + encrypted-output patterns).
"""

import base64
import ctypes
import http.client
import io
import logging
import os
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional

from agents.base_agent import BaseAgent, AgentType
from core.decision_engine.llm_reasoner import LLMReasoner
from core.utils.flag_utils import find_first_flag
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
            "godot_game_loader",
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

        # --- Strategy 4: .NET assembly with encrypted embedded resource ---
        for binary in binaries:
            if is_pe_binary(binary):
                result = self._try_dotnet_resource(binary, challenge, steps)
                if result:
                    return result

        # --- Strategy 5: AES-NI self-decrypting shellcode (PE) ---
        for binary in binaries:
            if is_pe_binary(binary):
                result = self._try_aes_ni_shellcode(binary, challenge, steps)
                if result:
                    return result

        # --- Strategy 6: source code constraint solving ---
        for file_path in source_files:
            result = self._try_source_analysis(file_path, challenge, steps)
            if result:
                return result

        # --- Strategy 7: strings + LLM on any remaining file ---
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
            key = self._extract_godot_pck_key_from_pe(exe_files[0], steps)
            if key:
                steps.append(f"Extracted Godot PCK AES key: {key}")
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
                return self._result(challenge, "attempted", steps, flag=flag_tail)

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
    def _extract_godot_pck_key_from_pe(exe_file: str, steps: List[str]) -> Optional[str]:
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

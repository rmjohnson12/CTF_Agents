"""Unit tests for ReverseEngineeringAgent strategies."""
import hashlib
import os
import struct
import subprocess
import sys
import tempfile
import types
from unittest.mock import MagicMock, patch

import pytest

from agents.specialists.reverse_engineering.reverse_agent import (
    ReverseEngineeringAgent,
    _AES_SBOX,
    _AES_INV_SBOX,
    _glibc_rand,
    _glibc_srand,
    _ror8,
)
from core.utils.flag_utils import extract_flags, find_first_flag
from tools.common.elf_utils import is_elf_binary, is_native_binary, is_pe_binary


# ---------------------------------------------------------------------------
# flag_utils: false-positive regression tests
# ---------------------------------------------------------------------------

class TestFlagUtilsRegression:
    def test_rejects_lowercase_arbitrary_prefix(self):
        # binary noise like "xyz{rrrr|}" must not be accepted
        assert find_first_flag("abcrrrrxyz{rrrr|}") is None

    def test_rejects_two_char_lowercase_prefix(self):
        assert find_first_flag("ab{something_here}") is None

    def test_accepts_htb(self):
        assert find_first_flag("HTB{real_flag_here}") == "HTB{real_flag_here}"

    def test_accepts_ctf(self):
        assert find_first_flag("CTF{real_flag_here}") == "CTF{real_flag_here}"

    def test_accepts_flag_lowercase(self):
        assert find_first_flag("flag{real_flag_here}") == "flag{real_flag_here}"

    def test_accepts_picocTF(self):
        assert find_first_flag("picoCTF{g3t_r3kt}") == "picoCTF{g3t_r3kt}"

    def test_accepts_thm(self):
        assert find_first_flag("THM{tryhackme}") == "THM{tryhackme}"

    def test_accepts_ductf(self):
        assert find_first_flag("DUCTF{downunder}") == "DUCTF{downunder}"

    def test_accepts_multiword_uppercase_prefix(self):
        assert find_first_flag("UACTF{some_flag}") == "UACTF{some_flag}"

    def test_accepts_uscg_formats(self):
        # US Cyber Games flag formats
        assert find_first_flag("SVIUSCG{This_is_a_Flag}") == "SVIUSCG{This_is_a_Flag}"
        assert find_first_flag("SVBRG{This_is_a_Flag}") == "SVBRG{This_is_a_Flag}"
        assert find_first_flag("SVIBGR{jw7_4i_7rus7_issu3}") == "SVIBGR{jw7_4i_7rus7_issu3}"

    def test_uscg_prefixes_registered(self):
        from core.utils.flag_utils import KNOWN_FLAG_PREFIXES
        for p in ("SVIUSCG{", "SVIBGR{", "SVBRG{"):
            assert p in KNOWN_FLAG_PREFIXES

    def test_rejects_mixed_case_unknown(self):
        # Mixed-case unknown platform should not match
        assert find_first_flag("xYz{some_flag_here}") is None


# ---------------------------------------------------------------------------
# glibc rand reimplementation
# ---------------------------------------------------------------------------

class TestGlibcRand:
    def test_deterministic_first_value(self):
        state, fptr, rptr = _glibc_srand(12345)
        v, _, _ = _glibc_rand(state, fptr, rptr)
        assert v == 383100999

    def test_different_seeds_differ(self):
        s1, f1, r1 = _glibc_srand(1)
        s2, f2, r2 = _glibc_srand(2)
        v1, _, _ = _glibc_rand(s1, f1, r1)
        v2, _, _ = _glibc_rand(s2, f2, r2)
        assert v1 != v2

    def test_seed_zero_treated_as_one(self):
        s0, f0, r0 = _glibc_srand(0)
        s1, f1, r1 = _glibc_srand(1)
        v0, _, _ = _glibc_rand(s0, f0, r0)
        v1, _, _ = _glibc_rand(s1, f1, r1)
        assert v0 == v1

    def test_ror8(self):
        assert _ror8(0b10110001, 1) == 0b11011000
        assert _ror8(0xFF, 0) == 0xFF
        assert _ror8(0x01, 1) == 0x80


# ---------------------------------------------------------------------------
# _parse_rodata_strings
# ---------------------------------------------------------------------------

class TestParseRodataStrings:
    def _make_objdump(self, hex_words: list[str]) -> str:
        lines = ["Contents of section .rodata:"]
        for i, word in enumerate(hex_words):
            addr = f"{i * 4:04x}"
            lines.append(f" {addr} {word}                                  ....")
        return "\n".join(lines)

    def test_basic_string(self):
        # "HTB\x00" → one word
        word = bytes(b"HTB\x00").hex()
        out = self._make_objdump([word])
        result = ReverseEngineeringAgent._parse_rodata_strings(out)
        assert "HTB" in result

    def test_multiple_strings(self):
        # "Itz\x00" + "_0n\x00"
        w1 = bytes(b"Itz\x00").hex()
        w2 = bytes(b"_0n\x00").hex()
        out = self._make_objdump([w1, w2])
        result = ReverseEngineeringAgent._parse_rodata_strings(out)
        assert "Itz" in result
        assert "_0n" in result

    def test_ignores_non_printable(self):
        word = bytes([0x01, 0x02, 0x03, 0x00]).hex()
        out = self._make_objdump([word])
        result = ReverseEngineeringAgent._parse_rodata_strings(out)
        assert result == []


# ---------------------------------------------------------------------------
# indexed XOR/add phrase verifier
# ---------------------------------------------------------------------------

class TestIndexedXorPhrase:
    DISASM = """
      4011e5:\te8 56 fe ff ff       \tcallq\t0x401040 <strlen@plt>
      4011ea:\t48 83 f8 17          \tcmpq\t$0x17, %rax
      401212:\t48 8b 55 f8          \tmovq\t-0x8(%rbp), %rdx
      401216:\t48 89 d6             \tmovq\t%rdx, %rsi
      401219:\t89 c7                \tmovl\t%eax, %edi
      40121b:\te8 46 ff ff ff       \tcallq\t0x401166
      401220:\t48 8d 0d 09 0f 00 00\tleaq\t0xf09(%rip), %rcx        # 0x402130
      401231:\t38 d0                \tcmpb\t%dl, %al
      401241:\t48 83 7d f8 16       \tcmpq\t$0x16, -0x8(%rbp)
      401166:\t83 f0 13             \txorl\t$0x13, %eax
    """

    RODATA = """
    Contents of section .rodata:
     402130 40465c54 58466e78 287b7a2e 89593174  @F\\TXFnx({z..Y1t
     402140 30727335 8b3584                      0rs5.5.
    """

    def test_recovers_indexed_xor_phrase_from_objdump_outputs(self):
        candidate = ReverseEngineeringAgent._recover_indexed_xor_phrase_from_objdump(
            self.DISASM,
            self.RODATA,
        )

        assert candidate == "SVIBGR{b3ac0n_0v3rr1d3}"

    def test_strategy_solves_indexed_xor_phrase(self, tmp_path):
        binary = tmp_path / "beacon_override"
        binary.write_bytes(b"\x7fELF")
        agent = ReverseEngineeringAgent()
        steps = []

        def fake_run(args, **kwargs):
            if args[:2] == ["objdump", "-d"]:
                return MagicMock(stdout=self.DISASM, returncode=0)
            if args[:3] == ["objdump", "-s", "-j"]:
                return MagicMock(stdout=self.RODATA, returncode=0)
            raise AssertionError(f"unexpected command: {args}")

        with patch("subprocess.run", side_effect=fake_run):
            result = agent._try_indexed_xor_phrase(
                str(binary),
                {"id": "beacon", "category": "reverse"},
                steps,
            )

        assert result["status"] == "solved"
        assert result["flag"] == "SVIBGR{b3ac0n_0v3rr1d3}"
        assert any("indexed-XOR phrase candidate" in step for step in steps)


# ---------------------------------------------------------------------------
# _try_numeric_encoding
# ---------------------------------------------------------------------------

class TestNumericEncoding:
    def _make_agent(self):
        return ReverseEngineeringAgent()

    def _make_fake_binary(self, content: str) -> str:
        """Write a temp file with ELF magic so is_elf_binary returns True."""
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".elf")
        f.write(b"\x7fELF" + content.encode())
        f.close()
        return f.name

    def test_decodes_multiplier_16(self):
        # HTB{ok} encoded at *16
        encoded = " ".join(str(ord(c) * 16) for c in "HTB{ok_flag}")
        agent = self._make_agent()
        steps = []
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout=encoded.encode(), returncode=0
            )
            tmp = self._make_fake_binary("")
            try:
                result = agent._try_numeric_encoding(tmp, {"id": "t"}, steps)
            finally:
                os.unlink(tmp)
        assert result is not None
        assert result["flag"] == "HTB{ok_flag}"
        assert result["status"] == "solved"

    def test_returns_none_for_short_sequence(self):
        # Fewer than 8 numbers → not considered
        encoded = " ".join(str(ord(c) * 16) for c in "HTB{ok}")  # 7 chars
        agent = self._make_agent()
        steps = []
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout=encoded.encode(), returncode=0
            )
            tmp = self._make_fake_binary("")
            try:
                result = agent._try_numeric_encoding(tmp, {"id": "t"}, steps)
            finally:
                os.unlink(tmp)
        assert result is None

    def test_returns_none_for_non_flag_sequence(self):
        # Valid integers but decoded text has no flag
        encoded = " ".join(str(i * 16) for i in range(65, 85))  # 'ABCDE...'
        agent = self._make_agent()
        steps = []
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout=encoded.encode(), returncode=0
            )
            tmp = self._make_fake_binary("")
            try:
                result = agent._try_numeric_encoding(tmp, {"id": "t"}, steps)
            finally:
                os.unlink(tmp)
        assert result is None

    def test_returns_none_on_subprocess_error(self):
        agent = self._make_agent()
        steps = []
        with patch("subprocess.run", side_effect=Exception("boom")):
            tmp = self._make_fake_binary("")
            try:
                result = agent._try_numeric_encoding(tmp, {"id": "t"}, steps)
            finally:
                os.unlink(tmp)
        assert result is None


# ---------------------------------------------------------------------------
# _unpack_upx
# ---------------------------------------------------------------------------

class TestUnpackUpx:
    def _make_agent(self):
        return ReverseEngineeringAgent()

    def _make_elf(self) -> str:
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".elf")
        f.write(b"\x7fELF" + b"\x00" * 60)
        f.close()
        return f.name

    def test_skips_non_binary_file(self):
        agent = self._make_agent()
        steps = []
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        f.write(b"not a binary")
        f.close()
        try:
            result = agent._unpack_upx(f.name, steps)
            assert result == f.name
            assert steps == []
        finally:
            os.unlink(f.name)

    def test_skips_when_no_upx_marker(self):
        agent = self._make_agent()
        steps = []
        tmp = self._make_elf()
        try:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    stdout=b"some strings output without marker",
                    returncode=0,
                )
                result = agent._unpack_upx(tmp, steps)
            assert result == tmp
            assert steps == []
        finally:
            os.unlink(tmp)

    def test_unpacks_when_upx_marker_present(self):
        agent = self._make_agent()
        steps = []
        tmp = self._make_elf()
        created_files = []

        def fake_run(cmd, **kwargs):
            m = MagicMock()
            if cmd[0] == "strings":
                m.stdout = b"lots of stuff\nUPX 3.95\nmore stuff"
                m.returncode = 0
            else:
                # cmd is ["upx", "-d", src, "-o", dest]
                dest = cmd[cmd.index("-o") + 1]
                with open(dest, "wb") as f:
                    f.write(b"\x7fELF" + b"\x00" * 60)
                created_files.append(dest)
                m.returncode = 0
                m.stderr = b""
            return m

        try:
            with patch("subprocess.run", side_effect=fake_run):
                result = agent._unpack_upx(tmp, steps)
            # Should note that it unpacked the binary
            assert any("UPX" in s or "upx" in s.lower() for s in steps)
            # Result should differ from the original path
            assert result != tmp
        finally:
            os.unlink(tmp)
            for f in created_files:
                if os.path.exists(f):
                    os.unlink(f)

    def test_handles_missing_upx_tool(self):
        agent = self._make_agent()
        steps = []
        tmp = self._make_elf()

        def fake_run(cmd, **kwargs):
            m = MagicMock()
            if cmd[0] == "strings":
                m.stdout = b"UPX packed binary"
                m.returncode = 0
                return m
            raise FileNotFoundError("upx not found")

        try:
            with patch("subprocess.run", side_effect=fake_run):
                result = agent._unpack_upx(tmp, steps)
            assert result == tmp
            assert any("upx" in s.lower() for s in steps)
        finally:
            os.unlink(tmp)


# ---------------------------------------------------------------------------
# elf_utils: PE and ELF detection
# ---------------------------------------------------------------------------

class TestBinaryDetection:
    def _write_tmp(self, magic: bytes) -> str:
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(magic + b"\x00" * 60)
        f.close()
        return f.name

    def test_is_elf_binary_true(self):
        tmp = self._write_tmp(b"\x7fELF")
        try:
            assert is_elf_binary(tmp) is True
        finally:
            os.unlink(tmp)

    def test_is_elf_binary_false_for_pe(self):
        tmp = self._write_tmp(b"MZ")
        try:
            assert is_elf_binary(tmp) is False
        finally:
            os.unlink(tmp)

    def test_is_pe_binary_true(self):
        tmp = self._write_tmp(b"MZ")
        try:
            assert is_pe_binary(tmp) is True
        finally:
            os.unlink(tmp)

    def test_is_pe_binary_false_for_elf(self):
        tmp = self._write_tmp(b"\x7fELF")
        try:
            assert is_pe_binary(tmp) is False
        finally:
            os.unlink(tmp)

    def test_is_native_binary_true_for_elf(self):
        tmp = self._write_tmp(b"\x7fELF")
        try:
            assert is_native_binary(tmp) is True
        finally:
            os.unlink(tmp)

    def test_is_native_binary_true_for_pe(self):
        tmp = self._write_tmp(b"MZ")
        try:
            assert is_native_binary(tmp) is True
        finally:
            os.unlink(tmp)

    def test_is_native_binary_false_for_text(self):
        tmp = self._write_tmp(b"#!/usr/bin/env python3\n")
        try:
            assert is_native_binary(tmp) is False
        finally:
            os.unlink(tmp)

    def test_is_pe_binary_missing_file(self):
        assert is_pe_binary("/nonexistent/path.exe") is False

    def test_is_elf_binary_missing_file(self):
        assert is_elf_binary("/nonexistent/path.elf") is False


# ---------------------------------------------------------------------------
# PE binary: agent recognises .exe files as binaries
# ---------------------------------------------------------------------------

class TestDotnetResource:
    def _make_agent(self):
        return ReverseEngineeringAgent()

    def _make_pe(self, content: bytes = b"") -> str:
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
        f.write(b"MZ" + content)
        f.close()
        return f.name

    def test_skips_non_dotnet_pe(self):
        agent = self._make_agent()
        steps = []
        tmp = self._make_pe()
        try:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    stdout=b"some strings no dotnet markers", returncode=0
                )
                result = agent._try_dotnet_resource(tmp, {"id": "t"}, steps)
            assert result is None
        finally:
            os.unlink(tmp)

    def test_detects_dotnet_fingerprint(self):
        agent = self._make_agent()
        steps = []
        tmp = self._make_pe()
        try:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    stdout=b"mscorlib\nv4.0.30319\nSystem", returncode=0
                )
                # _extract_dotnet_flag will fail on fake PE; that's fine
                with patch.object(agent, "_extract_dotnet_flag", return_value=None):
                    with patch.object(agent, "_find_ilspycmd", return_value=None):
                        result = agent._try_dotnet_resource(tmp, {"id": "t"}, steps)
            assert any(".NET" in s for s in steps)
        finally:
            os.unlink(tmp)

    def test_shortest_candidate_selected(self):
        from core.utils.flag_utils import find_first_flag

        # Simulate: two HTB flags found, agent must pick shorter one
        agent = self._make_agent()
        strings = [
            "Nice here is the Flag:HTB{",
            "ThisIsAVeryLongKeyThatShouldNotBeTheFlag",
            "}",
            "ShortFlag",
        ]
        # Manually exercise the candidate-selection logic
        candidates = []
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
        assert candidates
        best = min(candidates, key=len)
        assert best == "HTB{ShortFlag}"


class TestPESupport:
    def _make_agent(self):
        return ReverseEngineeringAgent()

    def _make_pe(self) -> str:
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
        f.write(b"MZ" + b"\x00" * 60)
        f.close()
        return f.name

    def test_analyze_challenge_recognises_pe(self):
        agent = self._make_agent()
        tmp = self._make_pe()
        try:
            result = agent.analyze_challenge({
                "description": "reverse this",
                "files": [tmp],
                "tags": [],
            })
            assert result["can_handle"] is True
        finally:
            os.unlink(tmp)

    def test_numeric_encoding_works_on_pe(self):
        encoded = " ".join(str(ord(c) * 16) for c in "HTB{pe_flag_here}")
        agent = self._make_agent()
        steps = []
        tmp = self._make_pe()
        try:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    stdout=encoded.encode(), returncode=0
                )
                result = agent._try_numeric_encoding(tmp, {"id": "t"}, steps)
        finally:
            os.unlink(tmp)
        assert result is not None
        assert result["flag"] == "HTB{pe_flag_here}"

    def test_unpack_upx_runs_on_pe(self):
        agent = self._make_agent()
        steps = []
        tmp = self._make_pe()
        created = []

        def fake_run(cmd, **kwargs):
            m = MagicMock()
            if cmd[0] == "strings":
                m.stdout = b"UPX compressed"
                m.returncode = 0
            else:
                dest = cmd[cmd.index("-o") + 1]
                with open(dest, "wb") as f:
                    f.write(b"MZ" + b"\x00" * 60)
                created.append(dest)
                m.returncode = 0
                m.stderr = b""
            return m

        try:
            with patch("subprocess.run", side_effect=fake_run):
                result = agent._unpack_upx(tmp, steps)
            assert result != tmp
            assert any("UPX" in s or "upx" in s.lower() for s in steps)
        finally:
            os.unlink(tmp)
            for f in created:
                if os.path.exists(f):
                    os.unlink(f)


# ---------------------------------------------------------------------------
# _decrypt_xor_rol / _decrypt_xor_only (known-answer tests)
# ---------------------------------------------------------------------------

class TestDecryptMethods:
    def _make_agent(self):
        return ReverseEngineeringAgent()

    def _encrypt_xor_rol(self, seed: int, plaintext: bytes) -> bytes:
        """Mirror of the C encryptor: ROL then XOR."""
        from agents.specialists.reverse_engineering.reverse_agent import (
            _glibc_rand, _glibc_srand,
        )

        def _rol8(b: int, n: int) -> int:
            n &= 7
            return ((b << n) | (b >> (8 - n))) & 0xFF

        state, fptr, rptr = _glibc_srand(seed)
        out = bytearray()
        for b in plaintext:
            r1, fptr, rptr = _glibc_rand(state, fptr, rptr)
            r2, fptr, rptr = _glibc_rand(state, fptr, rptr)
            out.append(_rol8(b ^ (r1 & 0xFF), r2 & 7))
        return bytes(out)

    def test_xor_rol_roundtrip(self):
        agent = self._make_agent()
        seed = 0xDEADBEEF
        plaintext = b"HTB{test_flag_here}"
        ciphertext = self._encrypt_xor_rol(seed, plaintext)
        flag = agent._decrypt_xor_rol(seed, ciphertext, [])
        assert flag == "HTB{test_flag_here}"

    def test_xor_rol_wrong_seed_returns_none(self):
        agent = self._make_agent()
        seed = 0xDEADBEEF
        plaintext = b"HTB{test_flag_here}"
        ciphertext = self._encrypt_xor_rol(seed, plaintext)
        # Wrong seed → garbage, no valid flag
        assert agent._decrypt_xor_rol(seed + 1, ciphertext, []) is None

    def test_xor_only_roundtrip(self):
        from agents.specialists.reverse_engineering.reverse_agent import (
            _glibc_rand, _glibc_srand,
        )
        agent = self._make_agent()
        seed = 42
        plaintext = b"CTF{xor_only_test}"

        state, fptr, rptr = _glibc_srand(seed)
        ciphertext = bytearray()
        for b in plaintext:
            r, fptr, rptr = _glibc_rand(state, fptr, rptr)
            ciphertext.append(b ^ (r & 0xFF))

        flag = agent._decrypt_xor_only(seed, bytes(ciphertext), [])
        assert flag == "CTF{xor_only_test}"


# ---------------------------------------------------------------------------
# AES-NI instruction simulation (AESKEYGENASSIST + AESDECLAST)
# ---------------------------------------------------------------------------

class TestAesNiCrypto:
    """Known-answer tests for the AES-NI instruction simulation helpers."""

    def test_sbox_inverts_correctly(self):
        for i in range(256):
            assert _AES_INV_SBOX[_AES_SBOX[i]] == i

    def test_aeskeygenassist_rcon0_uniform_key(self):
        # key = [2]*16 → all SubWord bytes = S[2] = 0x77
        key = [2] * 16
        result = ReverseEngineeringAgent._aeskeygenassist(key, 0x00)
        assert result == [0x77] * 16

    def test_aeskeygenassist_rcon10_uniform_key(self):
        # key = [2]*16, rcon=0x10 → bytes 4 and 12 differ (RotWord gets XOR'd)
        key = [2] * 16
        result = ReverseEngineeringAgent._aeskeygenassist(key, 0x10)
        expected = [0x77] * 16
        expected[4]  = 0x77 ^ 0x10  # 0x67
        expected[12] = 0x77 ^ 0x10  # 0x67
        assert result == expected

    def test_aesdeclast_known_vector(self):
        # From partialencryption.exe: block_idx=2, enc=9d9d...8d9d...
        # Expected plaintext: 0xcc * 16
        enc  = list(bytes.fromhex("9d9d9d9d8d9d9d9d9d9d9d9d8d9d9d9d"))
        key  = [2] * 16
        rk0  = ReverseEngineeringAgent._aeskeygenassist(key, 0x00)
        rk1  = ReverseEngineeringAgent._aeskeygenassist(key, 0x10)
        tmp  = [enc[j] ^ rk1[j] for j in range(16)]
        result = ReverseEngineeringAgent._aesdeclast(tmp, rk0)
        assert result == [0xcc] * 16

    def test_decrypt_block_roundtrip(self):
        # block_idx=0 key=[0]*16, known ciphertext → known plaintext
        key   = [0] * 16
        rk0   = ReverseEngineeringAgent._aeskeygenassist(key, 0x00)
        rk1   = ReverseEngineeringAgent._aeskeygenassist(key, 0x10)
        plain = [0xAB] * 16
        # Encrypt: ShiftRows(SubBytes(plain XOR rk0)) XOR rk1
        import itertools
        sr_state = list(plain)
        sr_state = [_AES_SBOX[p ^ rk0[i]] for i, p in enumerate(sr_state)]
        # ShiftRows
        sr_state[1], sr_state[5], sr_state[9],  sr_state[13] = sr_state[5],  sr_state[9],  sr_state[13], sr_state[1]
        sr_state[2], sr_state[6], sr_state[10], sr_state[14] = sr_state[10], sr_state[14], sr_state[2],  sr_state[6]
        sr_state[3], sr_state[7], sr_state[11], sr_state[15] = sr_state[15], sr_state[3],  sr_state[7],  sr_state[11]
        enc = [sr_state[i] ^ rk1[i] for i in range(16)]
        # Decrypt and check
        result = ReverseEngineeringAgent._aes_ni_decrypt_block(enc, key)
        assert result == plain

    def test_decrypt_block_block2_cc_padding(self):
        # Concrete vector from partialencryption.exe
        enc = list(bytes.fromhex("9d9d9d9d8d9d9d9d9d9d9d9d8d9d9d9d"))
        key = [2] * 16
        assert ReverseEngineeringAgent._aes_ni_decrypt_block(enc, key) == [0xcc] * 16


# ---------------------------------------------------------------------------
# PE section parser
# ---------------------------------------------------------------------------

class TestPeSectionParser:
    def _build_minimal_pe(self, sections: list) -> bytes:
        """
        Build a minimal PE32+ with the given sections.
        sections = list of (name, vaddr, rawoff, rawsz, vsize)
        """
        pe_off = 0x80
        num_sections = len(sections)
        # DOS header
        dos = bytearray(pe_off)
        dos[0:2] = b"MZ"
        struct.pack_into("<I", dos, 0x3C, pe_off)

        # PE signature + COFF header (20 bytes)
        coff = bytearray(4 + 20)
        coff[0:4] = b"PE\x00\x00"
        struct.pack_into("<H", coff, 4 + 2, num_sections)  # NumberOfSections
        opt_size = 112  # PE32+ optional header size
        struct.pack_into("<H", coff, 4 + 16, opt_size)

        # Optional header (PE32+, 112 bytes minimum)
        opt = bytearray(opt_size)
        struct.pack_into("<H", opt, 0, 0x20B)   # PE32+ magic
        struct.pack_into("<Q", opt, 24, 0x140000000)  # ImageBase

        # Section table
        sect_table = bytearray(num_sections * 40)
        for i, (name, vaddr, rawoff, rawsz, vsize) in enumerate(sections):
            base = i * 40
            sect_table[base:base+8] = name.encode()[:8].ljust(8, b"\x00")
            struct.pack_into("<I", sect_table, base + 8,  vsize)
            struct.pack_into("<I", sect_table, base + 12, vaddr)
            struct.pack_into("<I", sect_table, base + 16, rawsz)
            struct.pack_into("<I", sect_table, base + 20, rawoff)

        return bytes(dos) + bytes(coff) + bytes(opt) + bytes(sect_table)

    def test_parses_two_sections(self):
        pe = self._build_minimal_pe([
            (".text",  0x1000, 0x400, 0x200, 0x180),
            (".data",  0x3000, 0x600, 0x100, 0x80),
        ])
        result = ReverseEngineeringAgent._parse_pe_sections(pe)
        assert len(result) == 2
        assert result[0][0] == ".text"
        assert result[0][1] == 0x1000    # vaddr
        assert result[0][2] == 0x400     # rawoff
        assert result[0][3] == 0x200     # rawsz
        assert result[0][4] == 0x180     # vsize
        assert result[1][0] == ".data"
        assert result[1][1] == 0x3000

    def test_image_base_pe32plus(self):
        pe = self._build_minimal_pe([])
        base = ReverseEngineeringAgent._pe_image_base(pe)
        assert base == 0x140000000

    def test_returns_empty_on_truncated_data(self):
        result = ReverseEngineeringAgent._parse_pe_sections(b"MZ\x00\x00")
        assert result == []


# ---------------------------------------------------------------------------
# AES-NI blob finder (parses objdump output)
# ---------------------------------------------------------------------------

class TestAesNiBlobFinder:
    def _make_agent(self):
        return ReverseEngineeringAgent()

    def test_finds_blob_from_objdump_pattern(self):
        objout = (
            "14000115a:\tmov\tedx,0x70\n"
            "14000115f:\tlea\trcx,[rip+0x2e9a]\t\t# 0x140004000\n"
            "140001166:\tcall\t0x140001050\n"
        )
        agent = ReverseEngineeringAgent()
        blobs = agent._find_aes_ni_blobs(objout, image_base=0x140000000)
        assert (0x4000, 0x70) in blobs

    def test_ignores_non_16_aligned_sizes(self):
        objout = (
            "14000115a:\tmov\tedx,0x71\n"
            "14000115f:\tlea\trcx,[rip+0x2e9a]\t\t# 0x140004000\n"
        )
        agent = ReverseEngineeringAgent()
        blobs = agent._find_aes_ni_blobs(objout, image_base=0x140000000)
        assert blobs == []

    def test_deduplicates_repeated_references(self):
        line = (
            "14000115a:\tmov\tedx,0x30\n"
            "14000115f:\tlea\trcx,[rip+0x100]\t\t# 0x140001100\n"
        )
        agent = ReverseEngineeringAgent()
        blobs = agent._find_aes_ni_blobs(line * 3, image_base=0x140000000)
        assert blobs.count((0x1100, 0x30)) == 1

    def test_multiple_blobs(self):
        objout = (
            "000:\tmov\tedx,0x70\n"
            "001:\tlea\trcx,[rip+0x0]\t\t# 0x140004000\n"
            "002:\tmov\tedx,0x30\n"
            "003:\tlea\trcx,[rip+0x0]\t\t# 0x1400040b0\n"
        )
        blobs = ReverseEngineeringAgent()._find_aes_ni_blobs(
            objout, image_base=0x140000000
        )
        assert (0x4000, 0x70) in blobs
        assert (0x40b0, 0x30) in blobs


# ---------------------------------------------------------------------------
# AES-NI character check extractor (capstone-based)
# ---------------------------------------------------------------------------

class TestAesNiCharExtraction:
    """Test _extract_aes_ni_char_checks using real decrypted shellcode bytes."""

    def test_extracts_h_at_position_0(self):
        pytest.importorskip("capstone")
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

        # Minimal stub: imul rcx,rcx,0 + cmp eax,0x48 ('H')
        # 48 6B C9 00          imul rcx, rcx, 0x0
        # 3D 48 00 00 00       cmp  eax, 0x48
        stub = bytes([
            0x48, 0x6B, 0xC9, 0x00,        # imul rcx, rcx, 0
            0x3D, 0x48, 0x00, 0x00, 0x00,  # cmp eax, 0x48
        ])
        checks = ReverseEngineeringAgent._extract_aes_ni_char_checks(stub, md)
        assert checks.get(0) == 0x48

    def test_extracts_multiple_positions(self):
        pytest.importorskip("capstone")
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

        # pos 0 → 'H' (0x48), pos 1 → 'T' (0x54)
        stub = bytes([
            0x48, 0x6B, 0xC9, 0x00,        # imul rcx, rcx, 0
            0x3D, 0x48, 0x00, 0x00, 0x00,  # cmp eax, 0x48
            0x48, 0x6B, 0xC9, 0x01,        # imul rcx, rcx, 1
            0x3D, 0x54, 0x00, 0x00, 0x00,  # cmp eax, 0x54
        ])
        checks = ReverseEngineeringAgent._extract_aes_ni_char_checks(stub, md)
        assert checks.get(0) == 0x48
        assert checks.get(1) == 0x54

    def test_empty_on_no_checks(self):
        pytest.importorskip("capstone")
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        # Just nops and ret
        stub = bytes([0x90, 0x90, 0x90, 0xC3])
        checks = ReverseEngineeringAgent._extract_aes_ni_char_checks(stub, md)
        assert checks == {}


# ---------------------------------------------------------------------------
# _try_aes_ni_shellcode integration (mocked)
# ---------------------------------------------------------------------------

class TestAesNiStrategy:
    def _make_pe(self) -> str:
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
        f.write(b"MZ" + b"\x00" * 60)
        f.close()
        return f.name

    def _make_agent(self):
        return ReverseEngineeringAgent()

    def test_skips_non_pe(self):
        agent = self._make_agent()
        steps = []
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".elf")
        f.write(b"\x7fELF" + b"\x00" * 60)
        f.close()
        try:
            result = agent._try_aes_ni_shellcode(f.name, {"id": "t"}, steps)
            assert result is None
        finally:
            os.unlink(f.name)

    def test_skips_pe_without_aes_ni(self):
        agent = self._make_agent()
        steps = []
        tmp = self._make_pe()
        try:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    stdout="normal x86 disassembly without aes instructions",
                    returncode=0,
                )
                result = agent._try_aes_ni_shellcode(tmp, {"id": "t"}, steps)
            assert result is None
        finally:
            os.unlink(tmp)

    def test_detects_aes_ni_and_reports(self):
        pytest.importorskip("capstone")
        agent = self._make_agent()
        steps = []
        tmp = self._make_pe()
        fake_objdump = (
            "aeskeygenassist xmm0, xmm0, 0x0\n"
            "aesdeclast xmm1, xmm0\n"
            "000:\tmov\tedx,0x70\n"
            "001:\tlea\trcx,[rip+0x0]\t\t# 0x140004000\n"
        )
        try:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    stdout=fake_objdump, returncode=0
                )
                # File open will fail on fake PE, so _try_aes_ni_shellcode
                # should record the detection step then return None
                with patch("builtins.open", side_effect=Exception("no real PE")):
                    result = agent._try_aes_ni_shellcode(tmp, {"id": "t"}, steps)
        finally:
            os.unlink(tmp)
        # Detection message must have been recorded before the open
        assert any("AES-NI" in s for s in steps)


# ---------------------------------------------------------------------------
# Godot game-loader helpers
# ---------------------------------------------------------------------------

class TestGodotGameLoader:
    def test_decodes_loader_arrays_and_decimal_join_cookie(self):
        script = """
        var jkoq = [0x5A, 0x7A, 0x52, 0x74, 0x4D, 0x32, 0x77, 0x77, 0x59, 0x57, 0x51, 0x7A, 0x63, 0x69, 0x31, 0x75, 0x5A, 0x58, 0x52, 0x33, 0x62, 0x33, 0x4A, 0x72, 0x4C, 0x6D, 0x68, 0x30, 0x59, 0x67, 0x3D, 0x3D]
        var ioqw = [0x63, 0x44, 0x51, 0x33, 0x62, 0x44, 0x42, 0x68, 0x5A, 0x46, 0x39, 0x69, 0x61, 0x57, 0x35, 0x68, 0x63, 0x6E, 0x6B, 0x3D]
        var loap = [0x52, 0x30, 0x52, 0x66, 0x54, 0x55, 0x42, 0x73, 0x64, 0x7A, 0x52, 0x79, 0x4D, 0x31, 0x39, 0x51, 0x51, 0x30, 0x49, 0x79, 0x4F, 0x54, 0x55, 0x30, 0x4D, 0x33, 0x30, 0x3D]
        var aklq = [0x39, 151, 0b110101, 31]
        var paic = [99, 105]
        """

        decoded = ReverseEngineeringAgent._decode_godot_loader_script(script)

        assert decoded["target_host"] == "g4m3l0ad3r-network.htb"
        assert decoded["payload_path"] == "p47l0ad_binary"
        assert decoded["flag_tail"] == "GD_M@lw4r3_PCB29543}"
        assert decoded["cookie"] == "57151533199105"

    def test_godot_loader_partial_tail_is_artifact_not_flag(self, tmp_path):
        script = tmp_path / "player.gd"
        script.write_text(
            """
            var loap = [0x52, 0x30, 0x52, 0x66, 0x54, 0x55, 0x42, 0x73, 0x64, 0x7A, 0x52, 0x79, 0x4D, 0x31, 0x39, 0x51, 0x51, 0x30, 0x49, 0x79, 0x4F, 0x54, 0x55, 0x30, 0x4D, 0x33, 0x30, 0x3D]
            """,
            encoding="utf-8",
        )
        agent = ReverseEngineeringAgent()

        result = agent._try_godot_game_loader(
            [str(script)],
            {"id": "godot_partial", "category": "reverse"},
            [],
        )

        assert result["status"] == "attempted"
        assert result.get("flag") is None
        assert result["artifacts"]["partial_flag_tail"] == "GD_M@lw4r3_PCB29543}"

    def test_native_pck_extraction_recovers_encrypted_gdscript(self, tmp_path):
        AES = pytest.importorskip("Crypto.Cipher.AES")
        key = bytes.fromhex("01" * 32)
        pck = tmp_path / "game.pck"
        script = b"var loap = [0x52, 0x30, 0x51, 0x3D]\n"
        file_iv = bytes.fromhex("02" * 16)
        dir_iv = bytes.fromhex("03" * 16)

        file_cipher = AES.new(key, AES.MODE_CFB, iv=file_iv, segment_size=128)
        encrypted_script = file_cipher.encrypt(
            script + (b"\0" * (ReverseEngineeringAgent._align16(len(script)) - len(script)))
        )
        file_blob = (
            hashlib.md5(script).digest()
            + struct.pack("<Q", len(script))
            + file_iv
            + encrypted_script
        )

        path = b"res://player/player.gd\0"
        directory = (
            struct.pack("<I", len(path))
            + path
            + struct.pack("<QQ", 0, len(file_blob))
            + hashlib.md5(file_blob).digest()
            + struct.pack("<I", 1)
        )
        dir_cipher = AES.new(key, AES.MODE_CFB, iv=dir_iv, segment_size=128)
        encrypted_dir = dir_cipher.encrypt(
            directory + (b"\0" * (ReverseEngineeringAgent._align16(len(directory)) - len(directory)))
        )

        file_base = 0x200
        header = bytearray(file_base)
        header[0:4] = b"GDPC"
        struct.pack_into("<I", header, 20, 1)
        struct.pack_into("<Q", header, 24, file_base)
        struct.pack_into("<I", header, 96, 1)
        header[100:116] = hashlib.md5(directory).digest()
        struct.pack_into("<Q", header, 116, len(directory))
        header[124:140] = dir_iv
        header[140 : 140 + len(encrypted_dir)] = encrypted_dir
        pck.write_bytes(bytes(header) + file_blob)

        steps = []
        recovered = ReverseEngineeringAgent._recover_godot_scripts_native(str(pck), key.hex(), steps)

        assert len(recovered) == 1
        assert open(recovered[0], "rb").read() == script
        assert any("native PCK extraction" in step for step in steps)

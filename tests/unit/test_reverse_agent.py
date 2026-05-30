"""Unit tests for ReverseEngineeringAgent strategies."""
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

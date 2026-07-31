"""ELF header decoding and host-execution compatibility.

A Linux challenge binary that cannot run on this host fails with a bare
``[Errno 8] Exec format error``, which is indistinguishable from a broken
payload. These tests pin the up-front check that tells the two apart.
"""
from __future__ import annotations

import pytest

from tools.common import elf_utils
from tools.common.elf_utils import elf_info, host_can_execute

EM_386 = 0x03
EM_ARM = 0x28
EM_X86_64 = 0x3E
EM_AARCH64 = 0xB7
EM_S390 = 0x16


ET_EXEC = 2
ET_DYN = 3


def _elf_bytes(
    machine: int = EM_X86_64,
    ei_class: int = 2,
    ei_data: int = 1,
    elf_type: int = ET_EXEC,
) -> bytes:
    """Synthesize the first 64 bytes of an ELF file with the given identity."""
    header = bytearray(b"\x00" * 20)
    header[0:4] = b"\x7fELF"
    header[4] = ei_class          # EI_CLASS: 1=32-bit, 2=64-bit
    header[5] = ei_data           # EI_DATA:  1=little, 2=big
    header[6] = 1                 # EI_VERSION
    endian = "little" if ei_data == 1 else "big"
    header[16:18] = elf_type.to_bytes(2, endian)
    header[18:20] = machine.to_bytes(2, endian)
    return bytes(header) + b"\x00" * 44


def _write(tmp_path, name="target", **kwargs):
    path = tmp_path / name
    path.write_bytes(_elf_bytes(**kwargs))
    return str(path)


# ---------------------------------------------------------------------------
# Header decoding
# ---------------------------------------------------------------------------

def test_decodes_64bit_little_endian_x86_64(tmp_path):
    info = elf_info(_write(tmp_path))

    assert info is not None
    assert info.bits == 64
    assert info.endian == "little"
    assert info.machine == EM_X86_64
    assert info.machine_name == "x86-64"
    assert info.docker_platform == "linux/amd64"


def test_decodes_32bit_arm(tmp_path):
    info = elf_info(_write(tmp_path, machine=EM_ARM, ei_class=1))

    assert info.bits == 32
    assert info.machine_name == "ARM"
    assert info.docker_platform == "linux/arm/v7"


def test_big_endian_s390_maps_to_its_real_platform(tmp_path):
    """linux/s390x is big-endian only, so endianness cannot blanket-disqualify."""
    info = elf_info(_write(tmp_path, machine=EM_S390, ei_data=2))

    assert info.endian == "big"
    assert info.docker_platform == "linux/s390x"


def test_big_endian_variant_of_a_little_endian_platform_is_refused(tmp_path):
    """linux/ppc64le exists; big-endian ppc64 must not be routed to it."""
    info = elf_info(_write(tmp_path, machine=0x15, ei_data=2))

    assert info.machine_name == "PowerPC64"
    assert info.docker_platform is None


def test_unknown_machine_is_named_not_crashed(tmp_path):
    info = elf_info(_write(tmp_path, machine=0x9999))

    assert "unknown" in info.machine_name
    assert info.docker_platform is None


@pytest.mark.parametrize("payload", [
    b"MZ\x90\x00" + b"\x00" * 60,      # PE, not ELF
    b"\x7fELF",                         # truncated before e_machine
    b"",                                # empty
])
def test_non_elf_and_truncated_return_none(tmp_path, payload):
    path = tmp_path / "artifact"
    path.write_bytes(payload)

    assert elf_info(str(path)) is None


def test_malformed_ei_class_returns_none(tmp_path):
    """The zero-filled stub used across the older tests is not a decodable ELF."""
    path = tmp_path / "stub"
    path.write_bytes(b"\x7fELF" + b"\x00" * 60)

    assert elf_info(str(path)) is None


def test_missing_file_returns_none(tmp_path):
    assert elf_info(str(tmp_path / "nope")) is None


# ---------------------------------------------------------------------------
# Host compatibility
# ---------------------------------------------------------------------------

def test_linux_elf_cannot_run_on_macos(tmp_path, monkeypatch):
    monkeypatch.setattr(elf_utils.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(elf_utils.platform, "machine", lambda: "arm64")

    runnable, reason = host_can_execute(_write(tmp_path))

    assert runnable is False
    assert "Darwin" in reason and "x86-64" in reason


def test_matching_linux_host_can_execute(tmp_path, monkeypatch):
    monkeypatch.setattr(elf_utils.platform, "system", lambda: "Linux")
    monkeypatch.setattr(elf_utils.platform, "machine", lambda: "x86_64")

    runnable, reason = host_can_execute(_write(tmp_path))

    assert runnable is True
    assert "natively" in reason


def test_foreign_arch_on_linux_cannot_execute(tmp_path, monkeypatch):
    monkeypatch.setattr(elf_utils.platform, "system", lambda: "Linux")
    monkeypatch.setattr(elf_utils.platform, "machine", lambda: "aarch64")

    runnable, reason = host_can_execute(_write(tmp_path, machine=EM_X86_64))

    assert runnable is False
    assert "aarch64" in reason and "x86-64" in reason


def test_x86_64_host_still_runs_32bit_x86(tmp_path, monkeypatch):
    monkeypatch.setattr(elf_utils.platform, "system", lambda: "Linux")
    monkeypatch.setattr(elf_utils.platform, "machine", lambda: "x86_64")

    runnable, _ = host_can_execute(_write(tmp_path, machine=EM_386, ei_class=1))

    assert runnable is True


def test_unknown_host_architecture_defers_to_a_real_exec(tmp_path, monkeypatch):
    """Refusing without evidence would block binaries an unlisted host runs fine."""
    monkeypatch.setattr(elf_utils.platform, "system", lambda: "Linux")
    monkeypatch.setattr(elf_utils.platform, "machine", lambda: "armv8l")

    runnable, reason = host_can_execute(_write(tmp_path))

    assert runnable is True
    assert "armv8l" in reason


def test_aarch64_host_can_run_32bit_arm(tmp_path, monkeypatch):
    """64-bit ARM kernels ship CONFIG_COMPAT, mirroring the x86_64/i386 case."""
    monkeypatch.setattr(elf_utils.platform, "system", lambda: "Linux")
    monkeypatch.setattr(elf_utils.platform, "machine", lambda: "aarch64")

    runnable, _ = host_can_execute(_write(tmp_path, machine=EM_ARM, ei_class=1))

    assert runnable is True


def test_bsd_hosts_are_not_refused_their_own_elf(tmp_path, monkeypatch):
    """FreeBSD and friends load ELF natively; only Darwin/Windows cannot."""
    monkeypatch.setattr(elf_utils.platform, "system", lambda: "FreeBSD")
    monkeypatch.setattr(elf_utils.platform, "machine", lambda: "amd64")

    runnable, _ = host_can_execute(_write(tmp_path))

    assert runnable is True


def test_undecodable_elf_header_does_not_claim_incompatibility(tmp_path, monkeypatch):
    """ELF magic with a corrupt header is unknown, not proven unrunnable."""
    monkeypatch.setattr(elf_utils.platform, "system", lambda: "Linux")
    monkeypatch.setattr(elf_utils.platform, "machine", lambda: "x86_64")
    path = tmp_path / "corrupt"
    path.write_bytes(b"\x7fELF" + b"\x00" * 60)

    runnable, reason = host_can_execute(str(path))

    assert runnable is True
    assert "could not be decoded" in reason


def test_pie_is_read_from_the_header_not_readelf(tmp_path):
    """readelf is absent on macOS, and shelling out to it failed open as non-PIE."""
    from agents.specialists.pwn.pwn_agent import PwnAgent

    pie = tmp_path / "pie"
    pie.write_bytes(_elf_bytes(elf_type=ET_DYN))
    static = tmp_path / "static"
    static.write_bytes(_elf_bytes(elf_type=ET_EXEC))

    agent = PwnAgent()

    assert agent._is_pie(str(pie)) is True
    assert agent._is_pie(str(static)) is False


def test_non_elf_defers_to_the_callers_normal_path(tmp_path):
    """A shell script or PE is not our call to block."""
    path = tmp_path / "script.sh"
    path.write_text("#!/bin/sh\necho hi\n")

    runnable, _ = host_can_execute(str(path))

    assert runnable is True

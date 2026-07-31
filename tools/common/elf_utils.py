"""Lightweight binary detection via magic bytes, plus ELF header decoding."""
from __future__ import annotations

import platform
from dataclasses import dataclass
from typing import Optional, Tuple

_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"

_MACHINE_NAMES = {
    0x03: "x86",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x15: "PowerPC64",
    0x16: "S/390",
    0x28: "ARM",
    0x2A: "SuperH",
    0x32: "IA-64",
    0x3E: "x86-64",
    0xB7: "AArch64",
    0xF3: "RISC-V",
}

# Platform strings `docker run --platform` accepts, keyed by (e_machine, endian).
# Endianness is part of the key because most of these platforms exist only in
# one byte order: linux/ppc64le is little-endian only, while linux/s390x is
# big-endian only, so a single per-machine mapping would be wrong for both.
_DOCKER_PLATFORMS = {
    (0x03, "little"): "linux/386",
    (0x15, "little"): "linux/ppc64le",
    (0x16, "big"): "linux/s390x",
    (0x28, "little"): "linux/arm/v7",
    (0x3E, "little"): "linux/amd64",
    (0xB7, "little"): "linux/arm64",
    (0xF3, "little"): "linux/riscv64",
}

# What the running host can execute natively, keyed by platform.machine().
# The 64-bit entries include their 32-bit compat architecture: x86_64 kernels
# ship IA32 emulation and arm64 kernels ship CONFIG_COMPAT almost universally.
# A missing 32-bit userland can still make such a binary fail, which is why the
# caller downgrades on a real ENOEXEC rather than trusting this table alone.
_HOST_MACHINES = {
    "x86_64": {0x3E, 0x03},
    "amd64": {0x3E, 0x03},
    "i386": {0x03},
    "i686": {0x03},
    "aarch64": {0xB7, 0x28},
    "arm64": {0xB7, 0x28},
    "armv7l": {0x28},
    "armv6l": {0x28},
    "riscv64": {0xF3},
    "ppc64le": {0x15},
    "s390x": {0x16},
}

# Operating systems that cannot load an ELF at all. Every other OS either is
# Linux or uses ELF natively (the BSDs, Solaris), so refusing there would block
# a binary the host runs fine.
_NON_ELF_SYSTEMS = {"Darwin", "Windows"}


ET_DYN = 3


@dataclass(frozen=True)
class ElfInfo:
    """The subset of the ELF header needed to decide how to run a binary."""

    bits: int
    endian: str
    osabi: int
    elf_type: int
    machine: int
    machine_name: str
    docker_platform: Optional[str]

    @property
    def is_pie(self) -> bool:
        """True for a position-independent executable (ET_DYN)."""
        return self.elf_type == ET_DYN


def is_elf_binary(path: str) -> bool:
    """Return True if *path* starts with the ELF magic bytes (``\\x7fELF``)."""
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == _ELF_MAGIC
    except (OSError, PermissionError):
        return False


def is_pe_binary(path: str) -> bool:
    """Return True if *path* is a Windows PE/EXE file (MZ magic bytes)."""
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == _PE_MAGIC
    except (OSError, PermissionError):
        return False


def is_native_binary(path: str) -> bool:
    """Return True if *path* is either an ELF or PE binary."""
    return is_elf_binary(path) or is_pe_binary(path)


def elf_info(path: str) -> Optional[ElfInfo]:
    """Decode *path*'s ELF identification bytes, or None if it is not an ELF.

    Only the first 20 bytes are read: e_ident plus e_type/e_machine.
    """
    try:
        with open(path, "rb") as fh:
            header = fh.read(20)
    except (OSError, PermissionError):
        return None

    if len(header) < 20 or header[:4] != _ELF_MAGIC:
        return None

    ei_class, ei_data = header[4], header[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return None

    endian = "little" if ei_data == 1 else "big"
    machine = int.from_bytes(header[18:20], endian)
    name = _MACHINE_NAMES.get(machine, f"unknown(0x{machine:x})")
    docker_platform = _DOCKER_PLATFORMS.get((machine, endian))

    return ElfInfo(
        bits=32 if ei_class == 1 else 64,
        endian=endian,
        osabi=header[7],
        elf_type=int.from_bytes(header[16:18], endian),
        machine=machine,
        machine_name=name,
        docker_platform=docker_platform,
    )


def host_can_execute(path: str) -> Tuple[bool, str]:
    """Return (can_run_natively, human_readable_reason) for *path*.

    An ELF cannot be exec'd on macOS or Windows no matter how the payload is
    built, and a foreign-architecture ELF cannot be exec'd without an emulator.
    Both cases surface from ``exec`` as a bare ``[Errno 8] Exec format error``,
    which reads like a broken payload rather than a host limitation, so callers
    should check here first and route to emulation instead of retrying.

    False is only returned on positive evidence of incompatibility. Anything
    unrecognized — an undecodable header, an unlisted host architecture — is
    reported as runnable so the caller attempts the exec and lets a real
    ``ENOEXEC`` settle it. Guessing "no" here would refuse binaries that run.
    """
    if not is_elf_binary(path):
        return True, "not an ELF binary"

    info = elf_info(path)
    if info is None:
        # ELF magic but an undecodable header: no evidence either way.
        return True, "ELF header could not be decoded"

    system = platform.system()
    if system in _NON_ELF_SYSTEMS:
        return False, (
            f"host OS is {system}, binary is a {info.bits}-bit {info.machine_name} ELF"
        )

    host_machine = platform.machine().lower()
    runnable = _HOST_MACHINES.get(host_machine)
    if runnable is None:
        return True, (
            f"unrecognized host architecture {host_machine!r}; attempting native execution"
        )
    if info.machine not in runnable:
        return False, (
            f"host architecture is {host_machine}, binary is {info.machine_name}"
        )
    if info.bits == 64 and host_machine in ("i386", "i686"):
        return False, f"host is 32-bit {host_machine}, binary is 64-bit"

    return True, f"{info.machine_name} runs natively on {host_machine}"

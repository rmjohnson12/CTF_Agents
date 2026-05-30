"""Lightweight binary detection via magic bytes."""
from __future__ import annotations

_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"


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

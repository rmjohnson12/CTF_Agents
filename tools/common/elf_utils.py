"""Lightweight ELF binary detection via magic bytes."""
from __future__ import annotations

_ELF_MAGIC = b"\x7fELF"


def is_elf_binary(path: str) -> bool:
    """Return True if *path* starts with the ELF magic bytes (``\\x7fELF``)."""
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == _ELF_MAGIC
    except (OSError, PermissionError):
        return False

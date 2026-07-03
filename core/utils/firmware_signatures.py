"""Content-based recognition of binary artifacts for deterministic routing.

Category routing that relies on the LLM (or a keyword heuristic) reading a prose
description is fragile: "Someone leaked the new Espresso firmware" classifies as
`reverse` on its own, even though the attached file is an ESP32 flash dump that
only the hardware specialist can decode. When we hold the actual bytes we can
route on ground truth instead of a guess, which is what stops this class of
intermittent misroute.

This module is a small, extensible registry of signature detectors. Add new
``(detector, category)`` pairs as more artifact types gain dedicated handling.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

# ESP-IDF flash layout: the partition table lives at 0x8000 and every entry
# starts with the little-endian magic 0x50AA. App partitions (type 0) point at
# an application image whose first byte is the ESP image magic 0xE9.
_ESP_PART_TABLE_OFFSET = 0x8000
_ESP_PART_ENTRY_MAGIC = 0x50AA
_ESP_IMAGE_MAGIC = 0xE9
_ESP_MIN_SIZE = 0x9000


def looks_like_esp32_firmware(path: str) -> bool:
    """True if *path* is an ESP32 flash dump with at least one real app image.

    The check is deliberately strict — partition-table magic at the fixed
    offset *and* a validated app image — so an arbitrary ``.bin`` cannot be
    misrouted to the hardware specialist on a coincidental byte match.
    """
    try:
        data = Path(path).read_bytes()
    except (OSError, ValueError):
        return False
    if len(data) < _ESP_MIN_SIZE:
        return False
    if struct.unpack_from("<H", data, _ESP_PART_TABLE_OFFSET)[0] != _ESP_PART_ENTRY_MAGIC:
        return False

    for entry_offset in range(_ESP_PART_TABLE_OFFSET, min(_ESP_PART_TABLE_OFFSET + 0x1000, len(data) - 32), 32):
        magic, part_type, _subtype, offset, _size, _label, _flags = struct.unpack_from(
            "<HBBII16sI", data, entry_offset
        )
        if magic == 0xFFFF:
            break
        if magic != _ESP_PART_ENTRY_MAGIC:
            break
        if part_type == 0 and offset < len(data) and data[offset] == _ESP_IMAGE_MAGIC:
            return True
    return False


# Registry of (content detector, routing category). Ordered by specificity.
_SIGNATURE_DETECTORS: List[Tuple[Callable[[str], bool], str]] = [
    (looks_like_esp32_firmware, "hardware"),
]


def category_for_file(path: str) -> Optional[str]:
    """Return the routing category implied by a single file's content, if any."""
    for detector, category in _SIGNATURE_DETECTORS:
        try:
            if detector(path):
                return category
        except Exception:
            continue
    return None


def category_for_files(files: Optional[Sequence[str]]) -> Optional[str]:
    """Return the first content-derived routing category across *files*."""
    for path in files or []:
        if not path:
            continue
        category = category_for_file(str(path))
        if category:
            return category
    return None

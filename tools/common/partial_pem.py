"""Structure recovery for partially redacted PEM private keys.

"Fractured key" CTF challenges hand out an RSA private key whose base64 body has
been mostly blanked out (asterisks, ASCII art, anything that is not a base64
character). Enough usually survives to break it: the opening lines carry the
entire modulus, and a surviving fragment further down carries the leading bits
of one prime, which is exactly the input Coppersmith needs to factor n.

This module does the bookkeeping - rebuilding the base64 grid, tracking which
bits are known down to sub-byte precision, and walking the PKCS#1 DER with that
partial knowledge. It performs no lattice work itself.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64_INDEX = {char: index for index, char in enumerate(B64_ALPHABET)}
_B64_BODY_CHARS = set(B64_ALPHABET + "=")

PEM_LINE_WIDTH = 64
DER_INTEGER = 0x02
DER_SEQUENCE = 0x30

# A base64 char carries 6 bits, so a truncated run leaves at most 6 dangling
# bits in the modulus. Allow a little more in case a mask starts mid-byte.
MAX_UNKNOWN_MODULUS_BITS = 20


@dataclass
class PrimeFragment:
    """Leading bits of one of the primes, recovered from a surviving run."""

    offset: int
    prime_bits: int
    known_high: int
    known_bits: int

    @property
    def unknown_bits(self) -> int:
        return self.prime_bits - self.known_bits

    @property
    def known_fraction(self) -> float:
        return self.known_bits / self.prime_bits if self.prime_bits else 0.0


@dataclass
class RedactedKey:
    """What could be read out of a redacted PKCS#1 RSA private key."""

    modulus_bits: int
    modulus_bytes: int
    modulus_candidates: List[int] = field(default_factory=list)
    modulus_unknown_bits: int = 0
    public_exponent: Optional[int] = None
    prime_fragments: List[PrimeFragment] = field(default_factory=list)


class PartialBytes:
    """A byte string where some bytes are known only down to their high bits."""

    def __init__(self) -> None:
        # offset -> (value of the leading `bits`, number of leading bits known)
        self._bits: Dict[int, Tuple[int, int]] = {}

    def set_high_bits(self, offset: int, value: int, bits: int) -> None:
        existing = self._bits.get(offset)
        if existing is None or existing[1] < bits:
            self._bits[offset] = (value, bits)

    def feed(self, offset: int, data: bytes, trailing: int, trailing_bits: int) -> None:
        """Record `data` at `offset`, then `trailing_bits` further known bits."""
        for index, byte in enumerate(data):
            self.set_high_bits(offset + index, byte, 8)
        position = offset + len(data)
        remaining = trailing_bits
        while remaining > 0:
            take = min(8, remaining)
            chunk = (trailing >> (remaining - take)) & ((1 << take) - 1)
            self.set_high_bits(position, chunk, take)
            remaining -= take
            position += 1

    def get(self, offset: int) -> Optional[int]:
        entry = self._bits.get(offset)
        if entry is None or entry[1] != 8:
            return None
        return entry[0]

    def get_range(self, offset: int, length: int) -> Optional[bytes]:
        out = bytearray()
        for index in range(length):
            byte = self.get(offset + index)
            if byte is None:
                return None
            out.append(byte)
        return bytes(out)

    def leading_bits(self, offset: int, limit: int) -> Tuple[int, int]:
        """Longest run of known bits starting at `offset`, capped at `limit` bytes.

        Returns (value, bit count) where value holds those leading bits.
        """
        value = 0
        bits = 0
        for index in range(limit):
            entry = self._bits.get(offset + index)
            if entry is None:
                break
            chunk, chunk_bits = entry
            value = (value << chunk_bits) | chunk
            bits += chunk_bits
            if chunk_bits != 8:
                break
        return value, bits

    def known_offsets(self) -> List[int]:
        return sorted(offset for offset, entry in self._bits.items() if entry[1] == 8)


def _pem_body_grid(text: str) -> Optional[str]:
    """Return the PEM body as one char string, '*' wherever a char is unknown.

    Redaction is destructive in both directions: it replaces base64 characters,
    and ASCII art can leave a line shorter than it started. Both are normalised
    back onto the original 64-column grid so byte offsets stay correct.
    """
    lines: List[str] = []
    inside = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("-----BEGIN"):
            inside = True
            continue
        if stripped.startswith("-----END"):
            break
        if inside:
            lines.append(line)

    if not lines:
        return None

    grid: List[str] = []
    for index, line in enumerate(lines):
        width = PEM_LINE_WIDTH if index < len(lines) - 1 else len(line)
        row = [char if char in _B64_BODY_CHARS else "*" for char in line[:width]]
        row.extend("*" * (width - len(row)))
        grid.append("".join(row))

    body = "".join(grid)
    return body + "*" * (-len(body) % 4)


def _decode_runs(body: str) -> List[Tuple[int, bytes, int, int]]:
    """Decode every 4-aligned run of known base64 chars.

    Yields (byte offset, whole bytes, trailing bit value, trailing bit count).
    A run that does not start on a 4-char boundary is dropped: its bits do not
    line up with a byte boundary, and such runs never occur in practice because
    redaction masks whole regions.
    """
    runs: List[Tuple[int, bytes, int, int]] = []
    index = 0
    while index < len(body):
        if body[index] == "*":
            index += 1
            continue
        end = index
        while end < len(body) and body[end] != "*":
            end += 1
        start, chunk = index, body[index:end]
        index = end
        if start % 4:
            shift = 4 - (start % 4)
            start, chunk = start + shift, chunk[shift:]
        if len(chunk) < 4:
            continue
        whole = len(chunk) // 4 * 4
        try:
            data = base64.b64decode(chunk[:whole])
        except Exception:
            continue
        trailing = 0
        trailing_bits = 0
        for char in chunk[whole:]:
            trailing = (trailing << 6) | _B64_INDEX[char]
            trailing_bits += 6
        runs.append((start * 3 // 4, data, trailing, trailing_bits))
    return runs


def _read_der_header(data: PartialBytes, offset: int) -> Optional[Tuple[int, int, int]]:
    """Return (tag, content length, header length) if the header is readable."""
    tag = data.get(offset)
    first_length = data.get(offset + 1)
    if tag is None or first_length is None:
        return None
    if first_length < 0x80:
        return tag, first_length, 2
    count = first_length & 0x7F
    if not 1 <= count <= 4:
        return None
    raw = data.get_range(offset + 2, count)
    if raw is None:
        return None
    return tag, int.from_bytes(raw, "big"), 2 + count


def looks_like_redacted_pem(text: str) -> bool:
    """True for a PEM whose base64 body has been partially masked out."""
    if "-----BEGIN" not in text or "PRIVATE KEY" not in text:
        return False
    body = _pem_body_grid(text)
    if body is None:
        return False
    return "*" in body


def parse_redacted_pem(text: str) -> Optional[RedactedKey]:
    """Recover the modulus and any usable prime fragment from a redacted PEM.

    Returns None when the surviving fragments do not pin down the modulus, which
    is the one piece the attack cannot work without.
    """
    body = _pem_body_grid(text)
    if body is None:
        return None

    data = PartialBytes()
    for offset, whole, trailing, trailing_bits in _decode_runs(body):
        data.feed(offset, whole, trailing, trailing_bits)

    outer = _read_der_header(data, 0)
    if outer is None or outer[0] != DER_SEQUENCE:
        return None

    cursor = outer[2]
    version = _read_der_header(data, cursor)
    if version is None or version[0] != DER_INTEGER:
        return None
    cursor += version[2] + version[1]

    modulus_header = _read_der_header(data, cursor)
    if modulus_header is None or modulus_header[0] != DER_INTEGER:
        return None
    _, modulus_length, modulus_header_length = modulus_header
    modulus_start = cursor + modulus_header_length
    if data.get(modulus_start) == 0x00:  # DER sign byte
        modulus_start += 1
        modulus_length -= 1
    modulus_bits = modulus_length * 8

    known_value, known_bits = data.leading_bits(modulus_start, modulus_length)
    unknown_bits = modulus_bits - known_bits
    if unknown_bits < 0 or unknown_bits > MAX_UNKNOWN_MODULUS_BITS:
        return None

    candidates = []
    for tail in range(1 << unknown_bits):
        candidate = (known_value << unknown_bits) | tail
        if candidate % 2:  # n = p*q is odd
            candidates.append(candidate)

    exponent = None
    exponent_offset = cursor + modulus_header_length + modulus_header[1]
    exponent_header = _read_der_header(data, exponent_offset)
    if exponent_header and exponent_header[0] == DER_INTEGER:
        raw = data.get_range(exponent_offset + exponent_header[2], exponent_header[1])
        if raw:
            exponent = int.from_bytes(raw, "big")

    return RedactedKey(
        modulus_bits=modulus_bits,
        modulus_bytes=modulus_length,
        modulus_candidates=candidates,
        modulus_unknown_bits=unknown_bits,
        public_exponent=exponent,
        prime_fragments=_find_prime_fragments(data, modulus_bits, modulus_start),
    )


def _find_prime_fragments(
    data: PartialBytes,
    modulus_bits: int,
    modulus_start: int,
    min_known_fraction: float = 0.51,
) -> List[PrimeFragment]:
    """Scan surviving bytes for a DER INTEGER holding a half-size prime.

    Walking the DER sequentially does not work here: the fields between the
    modulus and the primes (d in particular) are usually fully masked, so their
    headers are unreadable and the cursor is lost. Scanning for the distinctive
    half-size INTEGER header instead picks the primes up wherever they land.
    """
    prime_bits = modulus_bits // 2
    prime_bytes = prime_bits // 8
    fragments: List[PrimeFragment] = []

    for offset in data.known_offsets():
        if offset <= modulus_start or data.get(offset) != DER_INTEGER:
            continue
        header = _read_der_header(data, offset)
        if header is None:
            continue
        _, length, header_length = header
        if length not in (prime_bytes, prime_bytes + 1):
            continue
        start = offset + header_length
        if length == prime_bytes + 1:
            if data.get(start) != 0x00:
                continue
            start += 1

        known_high, known_bits = data.leading_bits(start, prime_bytes)
        if known_bits >= prime_bits:
            known_high >>= known_bits - prime_bits
            known_bits = prime_bits
        if known_bits < prime_bits * min_known_fraction:
            continue
        fragments.append(
            PrimeFragment(
                offset=start,
                prime_bits=prime_bits,
                known_high=known_high,
                known_bits=known_bits,
            )
        )

    fragments.sort(key=lambda fragment: fragment.known_bits, reverse=True)
    return fragments

"""Unit tests for recovering an RSA key from a partially redacted PEM.

Models the "Fractured Seal" pattern: a PKCS#1 private key whose base64 body is
mostly masked out, leaving the modulus and the leading bits of one prime. That
is enough for Coppersmith to recover the prime's masked low bits and factor n.

The fixture is a real exported PEM built from fixed primes, then masked, so the
parser is exercised against genuine DER rather than a hand-written layout.
"""
import base64

import pytest

from agents.specialists.cryptography.crypto_agent import CryptographyAgent
from tools.common.partial_pem import (
    PEM_LINE_WIDTH,
    looks_like_redacted_pem,
    parse_redacted_pem,
)

RSA = pytest.importorskip("Crypto.PublicKey.RSA", reason="pycryptodome is required")

# Fixed 256-bit primes -> a 512-bit modulus, so the lattice work stays instant.
_P = 115446922003183662990217062503570528263449617055928705831382564601241431350339
_Q = 109068648927878493546936916589276239019083284057827639367961518112906835268143
_E = 65537
_CIPHERTEXT = 5921575845419930989461714619750940212341215647136022172164028751445345789301166370597321687580356772915438145911233755165450985863912744809678702035627621
_FLAG = "HTB{unit_redacted_pem}"

# Leave the prime ~62% known: past Coppersmith's 50% floor with room to spare.
_KNOWN_PRIME_BYTES = 20


def _build_key_der() -> bytes:
    n = _P * _Q
    d = pow(_E, -1, (_P - 1) * (_Q - 1))
    pem = RSA.construct((n, _E, d, _P, _Q)).export_key().decode()
    body = "".join(
        line for line in pem.splitlines() if not line.startswith("-----")
    )
    return base64.b64decode(body)


def _redact(der: bytes, keep_char_ranges) -> str:
    """Re-emit `der` as a PEM, masking every base64 char outside the kept ranges."""
    body = base64.b64encode(der).decode()
    kept = ["*"] * len(body)
    for start, end in keep_char_ranges:
        for index in range(max(0, start), min(len(body), end)):
            kept[index] = body[index]
    masked = "".join(kept)
    lines = [masked[i:i + PEM_LINE_WIDTH] for i in range(0, len(masked), PEM_LINE_WIDTH)]
    return "\n".join(
        ["-----BEGIN RSA PRIVATE KEY-----", *lines, "-----END RSA PRIVATE KEY-----", ""]
    )


def _bytes_to_chars(start: int, end: int):
    """Char range covering byte range [start, end), rounded out to base64 groups."""
    return start // 3 * 4, -(-end // 3) * 4


def _fractured_pem() -> str:
    der = _build_key_der()
    n_bytes = (_P * _Q).to_bytes(64, "big")
    prime_bytes = _P.to_bytes(32, "big")

    modulus_end = der.index(n_bytes) + len(n_bytes)
    # Stop a few bits short of the modulus so its last byte survives only
    # partially - each base64 char carries 6 bits, so a mask almost never lands
    # on a byte boundary, and the parser has to reconstruct the missing bits.
    modulus_keep = (modulus_end * 8 - 1) // 6

    prime_start = der.index(prime_bytes)
    prime_keep = _bytes_to_chars(prime_start - 4, prime_start + _KNOWN_PRIME_BYTES)

    return _redact(der, [(0, modulus_keep), prime_keep])


def test_detects_redacted_pem():
    assert looks_like_redacted_pem(_fractured_pem()) is True
    assert looks_like_redacted_pem("just some base64 blob") is False


def test_intact_pem_is_not_flagged_as_redacted():
    der = _build_key_der()
    intact = _redact(der, [(0, len(base64.b64encode(der)))])
    assert looks_like_redacted_pem(intact) is False


def test_intact_pem_padding_is_not_treated_as_redaction():
    intact = "\n".join([
        "-----BEGIN PRIVATE KEY-----",
        "QQ==",
        "-----END PRIVATE KEY-----",
        "",
    ])

    assert looks_like_redacted_pem(intact) is False


def test_parses_modulus_and_prime_fragment():
    key = parse_redacted_pem(_fractured_pem())

    assert key is not None
    assert key.modulus_bits == 512
    assert 0 < key.modulus_unknown_bits <= 6
    assert _P * _Q in key.modulus_candidates

    assert key.prime_fragments, "expected a surviving prime fragment"
    fragment = key.prime_fragments[0]
    assert fragment.prime_bits == 256
    assert fragment.known_fraction > 0.5
    assert fragment.known_high == _P >> fragment.unknown_bits


def test_solves_redacted_pem_challenge(tmp_path):
    pytest.importorskip("fpylll", reason="fpylll is required for lattice reduction")
    pem = tmp_path / "fractured.pem"
    pem.write_text(_fractured_pem())
    enc = tmp_path / "flag.enc"
    enc.write_bytes(_CIPHERTEXT.to_bytes(64, "big"))

    agent = CryptographyAgent()
    steps = []
    plaintext = agent._try_redacted_pem_key_recovery_from_files(
        [str(pem), str(enc)], steps
    )

    assert plaintext is not None and _FLAG in plaintext
    assert any("factored the modulus" in step for step in steps)


def test_reports_when_no_prime_fragment_survives(tmp_path):
    der = _build_key_der()
    n_bytes = (_P * _Q).to_bytes(64, "big")
    modulus_only = _redact(der, [(0, _bytes_to_chars(0, der.index(n_bytes) + 64)[1])])

    pem = tmp_path / "modulus_only.pem"
    pem.write_text(modulus_only)

    agent = CryptographyAgent()
    steps = []
    assert agent._try_redacted_pem_key_recovery_from_files([str(pem)], steps) is None
    assert any("no prime fragment survived" in step for step in steps)


def test_analyze_challenge_flags_redacted_pem(tmp_path):
    pem = tmp_path / "fractured.pem"
    pem.write_text(_fractured_pem())

    analysis = CryptographyAgent().analyze_challenge(
        {"id": "t", "category": "crypto", "description": "a key survived the fire",
         "files": [str(pem)]}
    )
    assert "rsa_redacted_pem" in analysis["detected_types"]

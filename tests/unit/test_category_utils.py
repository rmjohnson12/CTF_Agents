"""Unit tests for canonical challenge-category normalization."""

import pytest

from core.utils.category_utils import normalize_category


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Hardware", "hardware"),
        ("hardware", "hardware"),
        ("Crypto", "crypto"),
        ("cryptography", "crypto"),
        ("Secure Coding", "secure_coding"),
        ("secure-coding", "secure_coding"),
        ("secure_coding", "secure_coding"),
        ("Reversing", "reverse"),
        ("rev", "reverse"),
        ("Binary", "pwn"),
        ("Binary Exploitation", "pwn"),
        ("Web", "web"),
        ("web_exploitation", "web"),
        ("Network", "networking"),
        ("Blockchain", "blockchain"),
        ("", "misc"),
        ("unknown", "misc"),
        (None, "misc"),
        ("  Log Analysis  ", "log"),
    ],
)
def test_normalize_category(raw, expected):
    assert normalize_category(raw) == expected


def test_normalize_category_is_idempotent():
    for value in ("Hardware", "cryptography", "Secure Coding", "Reversing", ""):
        once = normalize_category(value)
        assert normalize_category(once) == once

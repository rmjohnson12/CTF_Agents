"""Canonical challenge-category normalization.

Challenge categories reach the learning stores from several sources with
inconsistent spelling: HackTheBox emits Title-case names ("Hardware",
"Crypto", "Secure Coding"), local/example challenges use lowercase
("hardware", "crypto", "secure_coding"), and some agents pass synonyms
("cryptography", "reversing", "binary"). Persisted verbatim, these split the
performance history and solve-trace corpus so cross-run routing hints and
technique reuse never aggregate the HTB runs with the rest.

``normalize_category`` collapses all of these to one canonical key. Apply it at
every store boundary (write and read) so a single logical category maps to a
single row group regardless of who recorded it.
"""

from __future__ import annotations

import re

# Synonyms that should collapse onto a single canonical category. Keep these
# aligned with the coordinator's direct-route table so persisted history groups
# the same way routing decisions are made.
_CATEGORY_ALIASES = {
    "cryptography": "crypto",
    "reversing": "reverse",
    "rev": "reverse",
    "binary": "pwn",
    "binary_exploitation": "pwn",
    "pwnable": "pwn",
    "web_exploitation": "web",
    "network": "networking",
    "log_analysis": "log",
    "logs": "log",
    "hardware_logic": "hardware",
    "blockchain_exploitation": "blockchain",
}


def normalize_category(raw: object) -> str:
    """Return the canonical lowercase key for a challenge category.

    Empty/unknown input becomes ``"misc"``. Whitespace and hyphens fold to
    underscores, non-alphanumeric characters are dropped, then a small synonym
    table maps equivalents (e.g. ``cryptography`` -> ``crypto``) onto one key.
    """
    text = str(raw or "").strip().lower()
    if not text or text == "unknown":
        return "misc"
    text = re.sub(r"[\s\-]+", "_", text)
    text = re.sub(r"[^a-z0-9_]", "", text)
    text = text.strip("_")
    if not text:
        return "misc"
    return _CATEGORY_ALIASES.get(text, text)

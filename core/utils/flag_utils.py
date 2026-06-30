import re
from typing import List, Optional

# Canonical list of known flag prefixes (brace-style), most specific first.
# Used both for documentation and for known-plaintext attacks (e.g. XOR /
# stream-cipher keystream recovery), where the first bytes of the plaintext
# must be guessed. Keep USCG (US Cyber Games) variants near the front so the
# fallback solvers try them. Extend this single list instead of the per-file
# copies scattered across the agents.
KNOWN_FLAG_PREFIXES: List[str] = [
    "SVIUSCG{",  # US Cyber Games
    "SVIBGR{",   # US Cyber Games
    "SVBRG{",    # US Cyber Games
    "picoCTF{",
    "HTB{",
    "htb{",
    "CTF{",
    "flag{",
    "FLAG{",
    "SKY-",      # NCL style
    "NCL-",
]

# Common flag patterns: CTF{...}, HTB{...}, flag{...}, SKY-XXXX-####, etc.
# Pattern 1: Prefix{content} - Require a multi-character prefix and at least
# 4 chars inside to avoid source-code fragments like f"...{variable}".
# Prefix must be an all-uppercase acronym (HTB, CTF, THM, DUCTF…) or one of
# the known mixed-case platforms (picoCTF, nahamCon, …). This prevents false
# positives from binary noise like "xyz{rrrr|}" matching the broad pattern.
FLAG_REGEX_BRaces = re.compile(
    r"(flag|htb|picoCTF|nahamCon|[A-Z][A-Z0-9_-]+)"
    r"\{[a-zA-Z0-9_\-\.!@#$%^&*()+=|?><\/]{4,}\}"
)
# Pattern 2: SKY-XXXX-#### or NCL-XXXX-#### (NCL Style)
FLAG_REGEX_NCL = re.compile(r"(SKY|NCL)-[A-Z0-9]{4,}-[A-Z0-9-]+")

def extract_flags(text: str) -> List[str]:
    """
    Extracts all potential flags from a given text.
    Supports CTF{...}, HTB{...}, and NCL SKY-/NCL- formats.
    """
    if not text:
        return []
    
    flags = []
    # Match curly brace style
    for m in FLAG_REGEX_BRaces.finditer(text):
        candidate = m.group(0)
        if not _is_placeholder_flag(candidate):
            flags.append(candidate)
    # Match NCL style
    for m in FLAG_REGEX_NCL.finditer(text):
        flags.append(m.group(0))
        
    return flags


def _is_placeholder_flag(candidate: str) -> bool:
    body_match = re.search(r"\{([^{}]+)\}", candidate)
    if not body_match:
        return False
    body = body_match.group(1).strip().upper()
    placeholders = {
        "REDACTED",
        "PLACEHOLDER",
        "TODO",
        "FAKE",
        "FAKE_FLAG",
        "EXAMPLE",
        "YOUR_FLAG",
    }
    return body in placeholders


def find_first_flag(text: str) -> Optional[str]:
    """
    Returns the first flag found in the text, or None.
    """
    flags = extract_flags(text)
    return flags[0] if flags else None

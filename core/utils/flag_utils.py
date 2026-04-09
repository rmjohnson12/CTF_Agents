import re
from typing import List, Optional

# Common flag patterns: CTF{...}, HTB{...}, flag{...}, etc.
# Matches: Prefix followed by curly braces containing anything except a closing brace.
FLAG_REGEX = re.compile(r"([a-zA-Z0-9_-]+)?\{[a-zA-Z0-9_\-\.!@#$%^&*()+=|?><]+\}")

def extract_flags(text: str) -> List[str]:
    """
    Extracts all potential flags from a given text.
    Supports CTF{...}, HTB{...}, and other prefixed or unprefixed formats.
    """
    if not text:
        return []
    
    matches = FLAG_REGEX.finditer(text)
    return [m.group(0) for m in matches]

def find_first_flag(text: str) -> Optional[str]:
    """
    Returns the first flag found in the text, or None.
    """
    flags = extract_flags(text)
    return flags[0] if flags else None

import re
from typing import List, Optional

# Common flag patterns: CTF{...}, HTB{...}, flag{...}, SKY-XXXX-####, etc.
# Pattern 1: Prefix{content} - Require a multi-character prefix and at least
# 4 chars inside to avoid source-code fragments like f"...{variable}".
FLAG_REGEX_BRaces = re.compile(r"([a-zA-Z0-9_-]{2,})\{[a-zA-Z0-9_\-\.!@#$%^&*()+=|?><]{4,}\}")
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
        flags.append(m.group(0))
    # Match NCL style
    for m in FLAG_REGEX_NCL.finditer(text):
        flags.append(m.group(0))
        
    return flags

def find_first_flag(text: str) -> Optional[str]:
    """
    Returns the first flag found in the text, or None.
    """
    flags = extract_flags(text)
    return flags[0] if flags else None

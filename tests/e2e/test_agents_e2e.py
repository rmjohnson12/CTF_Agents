"""
End-to-end agent tests.

Each test exercises the full pipeline:
  challenge JSON  →  CoordinatorAgent (heuristic routing)
                  →  specialist agent
                  →  real tool execution
                  →  flag extraction

No LLM key is required — all tests use the heuristic fallback path.
Tests that depend on external binaries are skipped when those binaries
are absent so the suite stays green in bare environments.
"""

import shutil
from pathlib import Path
from typing import Optional

import pytest

# ── coordinator factory (mirrors ask.py setup) ────────────────────────

def build_coordinator():
    from agents.coordinator.coordinator_agent import CoordinatorAgent
    from agents.specialists.cryptography.crypto_agent import CryptographyAgent
    from agents.specialists.forensics.forensics_agent import ForensicsAgent
    from agents.specialists.log_analysis.log_agent import LogAnalysisAgent
    from agents.specialists.misc.coding_agent import CodingAgent
    from agents.specialists.reverse_engineering.reverse_agent import ReverseEngineeringAgent
    from tools.crypto.hashcat import HashcatTool
    from tools.crypto.john import JohnTool

    john = JohnTool()
    hashcat = HashcatTool()

    coordinator = CoordinatorAgent()
    coordinator.register_agent(CryptographyAgent(john_tool=john, hashcat_tool=hashcat))
    coordinator.register_agent(ForensicsAgent(john_tool=john, hashcat_tool=hashcat))
    coordinator.register_agent(LogAnalysisAgent())
    coordinator.register_agent(ReverseEngineeringAgent())
    coordinator.register_agent(CodingAgent())
    return coordinator


FIXTURES = Path(__file__).parent / "fixtures"

# ── skip markers ──────────────────────────────────────────────────────

needs_john     = pytest.mark.skipif(not shutil.which("john"),     reason="john not installed")
needs_hashcat  = pytest.mark.skipif(not shutil.which("hashcat"),  reason="hashcat not installed")
needs_strings  = pytest.mark.skipif(not shutil.which("strings"),  reason="strings not installed")
needs_rockyou  = pytest.mark.skipif(
    not any(
        Path(p).exists() for p in [
            str(Path.home() / "Downloads" / "rockyou.txt"),
            "/usr/share/wordlists/rockyou.txt",
            "shared/wordlists/passwords/rockyou.txt",
        ]
    ),
    reason="rockyou.txt not found",
)
needs_wordlist = pytest.mark.skipif(
    not Path("my_passwords.txt").exists(),
    reason="my_passwords.txt not found in working directory",
)


# ── CRYPTO: Caesar cipher ─────────────────────────────────────────────

def test_crypto_caesar_e2e():
    """
    Caesar-3 encoded 'Hello World' → agent decodes to 'Hello World'.
    No external tools needed.
    """
    challenge = {
        "id": "e2e_caesar_001",
        "name": "Caesar Cipher",
        "category": "crypto",
        "description": "Decrypt this caesar cipher: 'Khoor Zruog'",
        "hints": ["Try shifting the letters"],
        "tags": ["crypto", "caesar"],
        "files": [],
        "metadata": {},
    }

    result = build_coordinator().solve_challenge(challenge)

    assert result["status"] == "solved", f"Expected solved, got {result['status']}. Steps: {result.get('steps')}"
    assert result["flag"] is not None
    assert "Hello World" in result["flag"] or "hello world" in result["flag"].lower()


# ── CRYPTO: Base64 decode ─────────────────────────────────────────────

def test_crypto_base64_e2e():
    """
    Base64-encoded CTF flag in description → agent decodes and extracts it.
    No external tools needed.
    Q1RGe2Jhc2U2NF9mbGFnfQ== decodes to CTF{base64_flag}
    """
    challenge = {
        "id": "e2e_base64_001",
        "name": "Base64 Challenge",
        "category": "crypto",
        "description": "Q1RGe2Jhc2U2NF9mbGFnfQ==",
        "hints": [],
        "tags": ["crypto", "encoding"],
        "files": [],
        "metadata": {},
    }

    result = build_coordinator().solve_challenge(challenge)

    assert result["status"] == "solved", f"Steps: {result.get('steps')}"
    assert result["flag"] == "CTF{base64_flag}"


# ── CRYPTO: Hash cracking with explicit wordlist ──────────────────────

@needs_wordlist
@needs_hashcat
def test_crypto_hash_crack_with_wordlist_e2e():
    """
    MD5 hash of 'Sup3rS3cret!' cracked using my_passwords.txt.
    Requires: hashcat, my_passwords.txt in working directory.
    """
    challenge = {
        "id": "e2e_hash_wordlist_001",
        "name": "Hash Crack",
        "category": "crypto",
        "description": "Crack this hash: 8bc12637e39435c402bfba520cc1b711",
        "hints": ["It's MD5"],
        "tags": ["crypto", "hash"],
        "files": [str(Path("my_passwords.txt").resolve())],
        "metadata": {},
    }

    result = build_coordinator().solve_challenge(challenge)

    assert result["status"] == "solved", f"Steps: {result.get('steps')}"
    assert result["flag"] == "Sup3rS3cret!"


# ── CRYPTO: Hash cracking with rockyou fallback ───────────────────────

@needs_rockyou
@needs_hashcat
def test_crypto_hash_crack_rockyou_fallback_e2e():
    """
    MD5 hash of 'emilybffl' — NOT in my_passwords.txt.
    Agent must fall back to rockyou.txt and crack it there.
    Requires: hashcat, ~/Downloads/rockyou.txt (or system rockyou).
    """
    challenge = {
        "id": "e2e_hash_rockyou_001",
        "name": "Hash Crack Rockyou",
        "category": "crypto",
        "description": "Crack this MD5 hash: 68a96446a5afb4ab69a2d15091771e39",
        "hints": [],
        "tags": ["crypto", "hash"],
        "files": [],
        "metadata": {},
    }

    result = build_coordinator().solve_challenge(challenge)

    assert result["status"] == "solved", f"Steps: {result.get('steps')}"
    assert result["flag"] == "emilybffl"


# ── REVERSE ENGINEERING: Python constraint solving ────────────────────

def test_reverse_constraint_solving_e2e():
    """
    reverse_me.py encodes three constraints (length, sum, fixed char).
    The reverse agent statically extracts them and solves without LLM.
    Expected password: 'hbTbbbbb'
    """
    fixture = FIXTURES / "reverse_me.py"
    challenge = {
        "id": "e2e_reverse_001",
        "name": "Reverse the Program",
        "category": "reverse",
        "description": "Authenticate the program to get the flag",
        "hints": ["Analyze the source code constraints"],
        "tags": ["reverse", "python"],
        "files": [str(fixture)],
        "metadata": {},
    }

    result = build_coordinator().solve_challenge(challenge)

    assert result["status"] == "solved", f"Steps: {result.get('steps')}"
    assert result["flag"] == "hbTbbbbb"


# ── LOG ANALYSIS: Brute force IP detection ────────────────────────────

def test_log_brute_force_detection_e2e():
    """
    auth.log has 20 failed SSH attempts from 192.168.1.50 and 2 from other IPs.
    The log agent identifies 192.168.1.50 as the brute-force source.
    No external tools needed.
    """
    fixture = FIXTURES / "auth_events.txt"
    challenge = {
        "id": "e2e_log_001",
        "name": "Brute Force Detection",
        "category": "log",
        "description": "Analyze the auth log and identify which IP executed a brute force SSH attack",
        "hints": [],
        "tags": ["log", "ssh"],
        "files": [str(fixture)],
        "metadata": {},
    }

    result = build_coordinator().solve_challenge(challenge)

    assert result["status"] == "solved", f"Steps: {result.get('steps')}"
    assert result["flag"] == "192.168.1.50"


# ── FORENSICS: Flag embedded in binary (strings) ──────────────────────

@needs_strings
def test_forensics_strings_extraction_e2e():
    """
    suspicious.bin contains 'CTF{found_in_binary_strings}' among binary noise.
    The forensics agent extracts it via the strings tool.
    Requires: strings binary.
    """
    fixture = FIXTURES / "suspicious.dat"
    challenge = {
        "id": "e2e_forensics_001",
        "name": "Binary Artifact",
        "category": "forensics",
        "description": "Analyze this binary artifact and extract any hidden data",
        "hints": ["Try strings analysis"],
        "tags": ["forensics", "strings"],
        "files": [str(fixture)],
        "metadata": {},
    }

    result = build_coordinator().solve_challenge(challenge)

    assert result["status"] == "solved", f"Steps: {result.get('steps')}"
    assert result["flag"] == "CTF{found_in_binary_strings}"

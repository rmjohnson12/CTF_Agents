"""
Evaluation fixture tests.

Each test exercises the full pipeline using a realistic challenge JSON file
sourced from the challenges/evaluation/ directory:

  parse_file (ChallengeParser)
    → CoordinatorAgent (heuristic routing)
    → specialist agent
    → flag extraction

These fixtures use CTFd and picoCTF export formats to validate the parser
integration end-to-end, and cover encoding paths not exercised by the
existing synthetic e2e tests.

No LLM key or external tools are required.  All three tests pass on a bare
environment with only the Python dependencies installed.

Design notes:
  - Fixture 1 (CTFd format): decimal ASCII encoding.  ROT13 was rejected
    because the encoded form also matches the flag regex — the crypto agent
    would return the ciphertext as-is before attempting any decode.
  - Fixture 2 (picoCTF format): hex encoding.  The ciphertext is 30 hex chars
    (15 bytes), which avoids the 32/40/64/128-char hash-length heuristic that
    would redirect the agent toward hash cracking instead of hex decode.
  - Fixture 3 (native format): web access log, Apache Combined Log Format.
    The log agent's most-common-IP heuristic fires when "ip" and "most" both
    appear in the description.
"""

import shutil
from pathlib import Path

import pytest

from challenges.challenge_parser import ChallengeParser

EVAL_DIR = Path(__file__).resolve().parents[2] / "challenges" / "evaluation"
PROJ_ROOT = Path(__file__).resolve().parents[2]


def _resolve_files(challenge):
    """Expand relative file paths in a challenge dict to absolute paths."""
    challenge["files"] = [
        str((PROJ_ROOT / f).resolve()) if not Path(f).is_absolute() else f
        for f in challenge.get("files", [])
    ]
    return challenge


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


# ---------------------------------------------------------------------------
# Fixture 1: CTFd format — decimal ASCII encoding
# ---------------------------------------------------------------------------

def test_eval_ctfd_decimal_encoding():
    """
    CTFd export JSON:  value→points, flags[0]→flag, 'Cryptography'→'crypto'.
    The crypto agent detects and decodes space-separated ASCII decimal values.
    Expected flag: CTF{dec2asc}
    """
    challenge = ChallengeParser().parse_file(EVAL_DIR / "eval_crypto_decimal_ctfd.json")

    # Parser must have normalised the CTFd-specific fields
    assert challenge["points"] == 75, "CTFd 'value' field not mapped to 'points'"
    assert challenge["category"] == "crypto", "Category not normalised from 'Cryptography'"
    assert "type" not in challenge, "'type' field should be stripped by parser"
    assert challenge.get("flag") == "CTF{dec2asc}", "CTFd 'flags' list not collapsed to 'flag'"

    result = build_coordinator().solve_challenge(challenge)

    assert result["status"] == "solved", f"Expected solved. Steps:\n" + "\n".join(result.get("steps", []))
    assert result["flag"] == "CTF{dec2asc}"


# ---------------------------------------------------------------------------
# Fixture 2: picoCTF format — hex encoding
# ---------------------------------------------------------------------------

def test_eval_pico_hex_encoding():
    """
    picoCTF export JSON:  pid→id (string), value→points, 'Cryptography'→'crypto'.
    The crypto agent detects and decodes a 30-char hex string (15 bytes — not a
    hash length, so the hash-cracking branch is skipped).
    Expected flag: CTF{hex_d3c0de}
    """
    challenge = ChallengeParser().parse_file(EVAL_DIR / "eval_crypto_hex_pico.json")

    # Parser must have normalised the picoCTF-specific fields
    assert challenge["id"] == "9001", "picoCTF 'pid' not promoted to string 'id'"
    assert challenge["points"] == 50, "picoCTF 'value' field not mapped to 'points'"
    assert challenge["category"] == "crypto", "Category not normalised from 'Cryptography'"
    assert "pid" not in challenge, "'pid' field should be removed by parser"

    result = build_coordinator().solve_challenge(challenge)

    assert result["status"] == "solved", f"Expected solved. Steps:\n" + "\n".join(result.get("steps", []))
    assert result["flag"] == "CTF{hex_d3c0de}"


# ---------------------------------------------------------------------------
# Fixture 3: native format — web access log (Apache Combined Log)
# ---------------------------------------------------------------------------

def test_eval_log_web_access_most_common_ip():
    """
    Web access log with 40 requests from 172.16.42.200, 5 from 10.0.1.15, and
    3 from 203.0.113.8.  The log agent's most-common-IP heuristic fires because
    both 'ip' and 'most' appear in the description.
    Expected flag: 172.16.42.200
    """
    artifact = EVAL_DIR / "artifacts" / "eval_access.log"
    assert artifact.exists(), f"Artifact missing: {artifact}"

    challenge = _resolve_files(
        ChallengeParser().parse_file(EVAL_DIR / "eval_log_webaccess.json")
    )

    result = build_coordinator().solve_challenge(challenge)

    assert result["status"] == "solved", f"Expected solved. Steps:\n" + "\n".join(result.get("steps", []))
    assert result["flag"] == "172.16.42.200"

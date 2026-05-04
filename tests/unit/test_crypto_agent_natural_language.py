from agents.specialists.cryptography.crypto_agent import CryptographyAgent


def test_crypto_agent_extracts_base64_from_natural_language_prompt():
    agent = CryptographyAgent()
    challenge = {
        "id": "nl_base64",
        "category": "crypto",
        "description": "Decode this base64 string: Q1RGe25hdHVyYWxfbGFuZ3VhZ2Vfd29ya3N9",
        "hints": [],
        "tags": ["crypto"],
        "files": [],
        "metadata": {},
    }

    result = agent.solve_challenge(challenge)

    assert result["status"] == "solved"
    assert result["flag"] == "CTF{natural_language_works}"
    assert "Extracted ciphertext: Q1RGe25hdHVyYWxfbGFuZ3VhZ2Vfd29ya3N9" in result["steps"]


def test_crypto_agent_extracts_hex_from_natural_language_prompt():
    agent = CryptographyAgent()
    challenge = {
        "id": "nl_hex",
        "category": "crypto",
        "description": "This looks like hex, decode it: 4354467b6865785f726f7574696e675f6f6b7d",
        "hints": [],
        "tags": ["crypto"],
        "files": [],
        "metadata": {},
    }

    result = agent.solve_challenge(challenge)

    assert result["status"] == "solved"
    assert result["flag"] == "CTF{hex_routing_ok}"
    assert "Extracted ciphertext: 4354467b6865785f726f7574696e675f6f6b7d" in result["steps"]

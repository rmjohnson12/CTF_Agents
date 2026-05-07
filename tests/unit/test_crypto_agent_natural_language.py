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


def test_crypto_agent_tries_caesar_for_simple_cipher_prompt():
    agent = CryptographyAgent()
    challenge = {
        "id": "nl_simple_cipher",
        "category": "crypto",
        "description": (
            "Decrypt the following message: 'pm ol ohk hufaopun jvumpkluaphs av zhf, "
            "ol dyval pa pu jpwoly, aoha pz, if zv johunpun aol vykly vm aol "
            "slaalyz vm aol hswohila, aoha uva h dvyk jvbsk il thkl vba.'. "
            "It seems to be encrypted with a simple cipher."
        ),
        "hints": [],
        "tags": ["crypto"],
        "files": [],
        "metadata": {},
    }

    result = agent.solve_challenge(challenge)

    assert result["status"] == "solved"
    assert result["flag"].startswith("if he had anything confidential to say")
    assert any("Detected types: caesar_cipher" in step for step in result["steps"])


def test_crypto_agent_solves_affine_mod256_source_and_hex_ciphertext(tmp_path):
    msg = b"Delivery on Friday.\nHTB{aff1n3_mod_256_shortcut}"
    encrypted = bytes((123 * b + 18) % 256 for b in msg)
    source = tmp_path / "chall.py"
    ciphertext = tmp_path / "msg.enc"
    source.write_text(
        "def encryption(msg):\n"
        "    ct = []\n"
        "    for char in msg:\n"
        "        ct.append((123 * char + 18) % 256)\n"
        "    return bytes(ct)\n"
    )
    ciphertext.write_text(encrypted.hex())

    result = CryptographyAgent().solve_challenge({
        "id": "affine_mod256",
        "category": "crypto",
        "description": "Decrypt the confidential message using the provided challenge script.",
        "files": [str(source), str(ciphertext)],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{aff1n3_mod_256_shortcut}"
    assert any("affine mod-256" in step for step in result["steps"])

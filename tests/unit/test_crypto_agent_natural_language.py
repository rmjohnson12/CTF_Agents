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


def test_crypto_agent_solves_chacha_known_plaintext_reuse(tmp_path):
    known = b"Known diplomatic message with enough bytes to reveal the stream."
    flag = b"HTB{stream_cipher_nonce_reuse}"
    keystream = bytes((i * 17 + 31) % 256 for i in range(len(known)))
    encrypted_known = bytes(a ^ b for a, b in zip(known, keystream))
    encrypted_flag = bytes(a ^ b for a, b in zip(flag, keystream))

    source = tmp_path / "source.py"
    output = tmp_path / "out.txt"
    source.write_text(
        "from Crypto.Cipher import ChaCha20\n\n"
        "if __name__ == '__main__':\n"
        "    message = b'Known diplomatic message with enough bytes '\n"
        "    message += b'to reveal the stream.'\n"
        "    encrypted_message = encryptMessage(message, key, iv)\n"
        "    encrypted_flag = encryptMessage(FLAG, key, iv)\n"
    )
    output.write_text(
        "00" * 12 + "\n" + encrypted_known.hex() + "\n" + encrypted_flag.hex()
    )

    result = CryptographyAgent().solve_challenge({
        "id": "chacha_reuse",
        "category": "crypto",
        "description": "Cha-Cha Ball stream cipher challenge. Decrypt the rest of the messages.",
        "files": [str(source), str(output)],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{stream_cipher_nonce_reuse}"
    assert any("stream-cipher keystream reuse" in step for step in result["steps"])


def test_crypto_agent_detects_rsa_time_capsule_needs_target(tmp_path):
    source = tmp_path / "server.py"
    source.write_text(
        "class TimeCapsule:\n"
        "    def __init__(self, msg):\n"
        "        self.e = 5\n"
        "    def get_new_time_capsule(self):\n"
        "        return {'time_capsule': 'AA', 'pubkey': ['BB', '5']}\n"
    )

    result = CryptographyAgent().solve_challenge({
        "id": "baby_time_capsule",
        "category": "crypto",
        "description": "Very easy crypto challenge.",
        "files": [str(source)],
    })

    assert result["status"] == "attempted"
    assert any("RSA broadcast pattern detected" in step for step in result["steps"])


def test_crypto_agent_rsa_broadcast_math_helpers_recover_plaintext():
    agent = CryptographyAgent()
    plaintext = b"flag"
    message = int.from_bytes(plaintext, "big")
    exponent = 5
    moduli = [
        10123457689,
        10123457701,
        10123457731,
        10123457747,
        10123457761,
    ]
    ciphertexts = [pow(message, exponent, modulus) for modulus in moduli]

    combined = agent._crt(ciphertexts, moduli)
    root, exact = agent._integer_nth_root(combined, exponent)

    assert exact
    assert agent._int_to_bytes(root) == plaintext

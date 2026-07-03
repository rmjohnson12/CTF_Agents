import pytest

from agents.specialists.cryptography.crypto_agent import CryptographyAgent
from core.utils.security import SecurityPolicyError


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


def test_crypto_agent_solves_source_backed_repeating_xor_despite_uuid_path(tmp_path):
    challenge_dir = tmp_path / "a12c7393-6f23-4166-821e-c31c1ec785fe"
    challenge_dir.mkdir()
    source = challenge_dir / "challenge.py"
    output = challenge_dir / "output.txt"
    source.write_text(
        "import os\n"
        "key = os.urandom(4)\n"
        "def encrypt(data):\n"
        "    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))\n"
    )
    output.write_text("Flag: 134af6e1297bc4a96f6a87fe046684e8047084ee046d84c5282dd7ef292dc9\n")

    result = CryptographyAgent().solve_challenge({
        "id": "repeating_xor",
        "category": "crypto",
        "description": f"Who needs AES when you have XOR? Files are in {challenge_dir}",
        "files": [str(source), str(output)],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{rep34t3d_x0r_n0t_s0_s3cur3}"
    assert result["steps"][2].startswith("Extracted ciphertext: Flag: 134af6")
    assert any("repeating-XOR" in step for step in result["steps"])
    assert result["artifacts"]["techniques"] == [
        "source_semantic_analysis",
        "repeating_xor_known_prefix",
    ]


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


def test_crypto_agent_solves_threebyte_rotate_xor_custom_cipher(tmp_path):
    source = tmp_path / "chall.py"
    output = tmp_path / "output.txt"
    source.write_text(
        "import secrets\n\n"
        "flag_input = b\"SVIUSCG{REDACTED}\"\n"
        "key = secrets.token_bytes(4)\n"
        "flag = bytearray(flag_input)\n"
        "kint = int.from_bytes(key, \"big\")\n"
        "for i in range(8):\n"
        "    for index in range(0, len(flag) - 2, 3):\n"
        "        h = flag[index]\n"
        "        h2 = flag[index+1]\n"
        "        h3 = flag[index+2]\n"
        "        h = h << 16\n"
        "        h2 = h2 << 8\n"
        "        ki = index % 8\n"
        "        hk = (kint >> (ki * 8)) & 0xff\n"
        "        xh3 = h3 ^ hk\n"
        "        th = h | h2 | xh3\n"
        "        r = th & 0x07\n"
        "        rh = ((th >> r) | (th << (24 - r))) & 0xffffff\n"
        "        flag[index] = (rh >> 16) & 0xff\n"
        "        flag[index+1] = (rh >> 8) & 0xff\n"
        "        flag[index+2] = rh & 0xff\n"
        "    kint = ((kint >> 3) | (kint << 61)) & 0xffffffffffffffff\n"
        "print(flag.hex())\n"
    )
    output.write_text("733ccc9554d04d1de8dac8f07d")

    result = CryptographyAgent().solve_challenge({
        "id": "threebyte_rotate_xor",
        "category": "crypto",
        "description": "Custom Python cipher with source and output.",
        "files": [str(source), str(output)],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "SVIUSCG{abcd}"
    assert any("3-byte rotate/XOR custom cipher" in step for step in result["steps"])


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


def test_crypto_agent_solves_local_rsa_low_exponent_unpadded_output(tmp_path):
    output = tmp_path / "output.txt"
    output.write_text(
        "N = 100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000039\n"
        "e = 3\n"
        "c1 = 30313234911758512392721422802742314667416215457043725356568186385012843750308212299054741027488591862576768807088146049888862437183800861374318579594536449125\n"
        "c2 = 30313234911758512392721422802742314667416215457043728273163082301629147057000259765169277712877317827480055173508743361558326230483438721152157454404227121656\n"
    )

    result = CryptographyAgent().solve_challenge({
        "id": "rsa_low_e",
        "category": "crypto",
        "description": "RSA e=3 related-message challenge.",
        "files": [str(output)],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "SVIUSCG{low_e_fixture}"
    assert any("RSA low-exponent" in step for step in result["steps"])


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


def test_crypto_agent_solves_rsa_partial_prime_leak_when_root_finder_available(tmp_path, monkeypatch):
    n = 6777416575772780455120361258643003332847866290477587026000820581850350458580817504900469611420276806052639728367466007688736561981368526042394026234839877
    c = 1863870912085629168191501817942076791250298950304900451762735907095681675638316722130546188324468339114688286310463557745447816228440098793152105489694767
    p_high = 74633293397496438820024045700863669312404786770390206301494878588362807050240
    low_bits = 4893723
    challenge_file = tmp_path / "challenge.txt"
    challenge_file.write_text(
        "# bottom 24 bits unknown\n"
        f"n = {n}\n"
        "e = 65537\n"
        f"p_high = {p_high}\n"
        f"c = {c}\n"
    )

    def fake_root_finder(cls, modulus, known_high, bound, steps):
        assert modulus == n
        assert known_high == p_high
        assert bound == 1 << 24
        return low_bits

    monkeypatch.setattr(
        CryptographyAgent,
        "_coppersmith_linear_factor_root",
        classmethod(fake_root_finder),
    )

    result = CryptographyAgent().solve_challenge({
        "id": "rsa_partial_prime",
        "category": "crypto",
        "description": "RSA-2048 prime leak challenge.",
        "files": [str(challenge_file)],
    })

    assert result["status"] == "solved"
    assert result["flag"] == "SVIUSCG{partial_prime_fixture}"
    assert any("RSA partial-prime leak" in step for step in result["steps"])


def test_crypto_time_capsule_socket_blocks_non_allowlisted_host(monkeypatch):
    monkeypatch.setenv("CTF_AGENTS_ALLOWED_NETWORKS", "localhost")

    with pytest.raises(SecurityPolicyError):
        CryptographyAgent._collect_time_capsule_samples("203.0.113.10", 31337, 1)

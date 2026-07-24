"""End-to-end test for the chosen-generator "false witness" bit oracle.

Models the HTB "False Witness" pattern: the server AES-ECB-encrypts the flag
under a random key, lets the player choose the generator G of H(m)=pow(G,m,P),
and exposes a per-bit oracle that returns a random integer for a 0-bit but a
value of the form G**sk mod P for a 1-bit. Sending G=P-1 collapses every 1-bit
witness to {1, P-1}, leaking the whole key. A faithful in-process mock server
drives the agent's real socket logic — no live network needed.
"""
import re
import secrets
import socket
import threading

import pytest

from agents.specialists.cryptography.crypto_agent import CryptographyAgent
from core.utils.security import temporary_allowed_networks

# A real 256-bit prime (the multiplicative group has an order-2 element P-1).
_P = 0xCD4A96D3B7FA7251A1BB765933FB676FCAE8C9026682E34F779122DFD66915BB
_FLAG = b"HTB{mock_false_witness_ok}"

# Source the agent inspects to recognize + parameterize the attack (128-bit key
# keeps the mock fast while remaining a valid AES-128 key length).
_SOURCE = f'''
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import secrets
P = {hex(_P)}
KEY = secrets.token_bytes(16)
KEY_BITS = list(map(int, f"{{int.from_bytes(KEY):0128b}}"))
def H(msg):
    return pow(G, msg, P)
G = int(input("give me the hashing generator: "))
print(AES.new(KEY, AES.MODE_ECB).encrypt(pad(FLAG, 16)).hex())
ret = secrets.randbelow(2**256) if KEY_BITS[i] == 0 else PK[i][secrets.randbelow(2)]
'''


def _mock_server(sock, key_bits, ct_hex):
    conn, _ = sock.accept()
    with conn:
        f = conn.makefile("rwb", buffering=0)
        f.write(b"Here is something for you:\n" + ct_hex.encode() + b"\n")
        f.write(b"Before we start, give me the hashing generator: ")
        g = int(f.readline().strip())
        cache = {}
        while True:
            f.write(b"1. Oracle\n2. Exit\n> ")
            choice = f.readline().strip()
            if choice == b"1":
                f.write(b"Enter offset: ")
                i = int(f.readline().strip())
                if i not in cache:
                    if key_bits[i] == 0:
                        cache[i] = secrets.randbelow(2 ** 256)
                    else:
                        # H(sk) with a random exponent; under G=P-1 this is in {1, P-1}.
                        cache[i] = pow(g, secrets.randbelow(2 ** 256), _P)
                f.write(b"Oracle result: " + str(cache[i]).encode() + b"\n")
            else:
                f.write(b"bye\n")
                break


def test_agent_solves_chosen_generator_bit_oracle(tmp_path):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    key = secrets.token_bytes(16)
    key_bits = list(map(int, f"{int.from_bytes(key):0128b}"))
    ct_hex = AES.new(key, AES.MODE_ECB).encrypt(pad(_FLAG, 16)).hex()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    thread = threading.Thread(target=_mock_server, args=(srv, key_bits, ct_hex), daemon=True)
    thread.start()

    src = tmp_path / "server.py"
    src.write_text(_SOURCE)
    challenge = {
        "id": "false_witness",
        "category": "crypto",
        "url": f"127.0.0.1:{port}",
        "files": [str(src)],
    }

    steps = []
    with temporary_allowed_networks(["127.0.0.1"]):
        flag = CryptographyAgent()._try_chosen_generator_bit_oracle(challenge, steps)
    thread.join(timeout=5)
    srv.close()

    assert flag == _FLAG.decode()


def test_detects_and_parameterizes_from_source():
    agent = CryptographyAgent
    assert agent._looks_like_chosen_generator_bit_oracle(_SOURCE) is True
    assert agent._extract_pow_modulus(_SOURCE) == _P
    assert agent._extract_key_bit_length(_SOURCE) == 128
    # A different crypto pattern must not be misdetected.
    assert agent._looks_like_chosen_generator_bit_oracle(
        "from Crypto.Cipher import AES\nq=getPrime(40); p=(2*q*r)+1\nAES.new(k, AES.MODE_ECB)"
    ) is False


def test_extract_tcp_target_handles_prose_and_dicts():
    ext = CryptographyAgent._extract_tcp_target
    assert ext({"description": "Remote crypto oracle at 154.57.164.73:32326"}) == ("154.57.164.73", 32326)
    assert ext({"target": {"host": "10.0.0.5", "port": 1337}}) == ("10.0.0.5", 1337)
    assert ext({"url": "nc example.htb 4444"}) == ("example.htb", 4444)
    assert ext({"description": "no target here"}) is None

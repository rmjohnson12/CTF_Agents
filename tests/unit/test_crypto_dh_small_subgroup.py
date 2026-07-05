"""Unit tests for the small-subgroup Diffie-Hellman oracle solver (no network).

Models the "Rhome" pattern: p = 2*q*r + 1 with a small prime q; the shared
secret is recovered by a discrete log in the order-q subgroup, then AES-ECB
decrypts the flag. Detection and math are driven from source, not hard-coded.
"""
from agents.specialists.cryptography.crypto_agent import CryptographyAgent

# Precomputed small-subgroup fixture (q ~22 bits, so >2^20 keeps it but DLog is instant).
_P = 4835742477789684786358967
_G = 2233352643992870549668373
_A = 838252219865580654664678
_B = 4208313320284039363863379
_CT = "fe474067941aa675f54fdd38a9f1d7f899d009e2709a7706f8aa4906c05cf9e6"
_FLAG = "HTB{unit_dh_subgroup}"

_SOURCE = """
from Crypto.Util.number import isPrime, long_to_bytes, getPrime
from Crypto.Cipher import AES
from hashlib import sha256
class DH:
    def gen(self):
        self.r = getPrime(512); self.q = getPrime(42)
        self.p = (2 * self.q * self.r) + 1
        self.g = pow(self.h, 2 * self.r, self.p)
"""


def test_detects_small_subgroup_dh_source():
    assert CryptographyAgent._looks_like_dh_small_subgroup(_SOURCE) is True
    assert CryptographyAgent._looks_like_dh_small_subgroup("just some xor cipher code") is False


def test_solves_small_subgroup_dh_oracle(tmp_path, monkeypatch):
    src = tmp_path / "server.py"
    src.write_text(_SOURCE)
    monkeypatch.setenv("CTF_AGENTS_ALLOWED_NETWORKS", "127.0.0.1")
    params = f"p = {_P}\ng = {_G}\nA = {_A}\nB = {_B}"
    monkeypatch.setattr(CryptographyAgent, "_query_dh_oracle",
                        staticmethod(lambda host, port, prompt=b"> ": (params, _CT)))

    agent = CryptographyAgent()
    steps = []
    flag = agent._try_dh_small_subgroup_oracle(
        {"id": "t", "files": [str(src)], "url": "http://127.0.0.1:9999"}, steps
    )
    assert flag == _FLAG
    assert any("discrete log" in s.lower() for s in steps)


def test_returns_none_without_tcp_target(tmp_path):
    src = tmp_path / "server.py"
    src.write_text(_SOURCE)
    agent = CryptographyAgent()
    # Source matches but no url/target -> cannot query, returns None (no crash).
    assert agent._try_dh_small_subgroup_oracle({"id": "t", "files": [str(src)]}, []) is None

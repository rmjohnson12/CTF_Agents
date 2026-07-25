"""Regression coverage for the bounded two-round AES save-oracle attack."""

import json
from types import SimpleNamespace

from agents.specialists.cryptography.crypto_agent import CryptographyAgent
from tools.crypto.two_round_aes import (
    DifferentialFamily,
    TwoRoundAesCipher,
    recover_master_key,
)


def _gf_mul(left: int, right: int) -> int:
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        left = ((left << 1) ^ (0x11B if left & 0x80 else 0)) & 0xFF
        right >>= 1
    return result


def _aes_sbox():
    values = []
    for value in range(256):
        inverse = 0 if value == 0 else next(
            candidate
            for candidate in range(1, 256)
            if _gf_mul(value, candidate) == 1
        )
        transformed = inverse
        for shift in (1, 2, 3, 4):
            transformed ^= (
                ((inverse << shift) | (inverse >> (8 - shift))) & 0xFF
            )
        values.append(transformed ^ 0x63)
    return tuple(values)


SBOX = _aes_sbox()
RCON = (0x00, 0x01, 0x02)
KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
FLAG = "HTB{two_round_agent_regression}"


def _base_state() -> bytes:
    return bytes.fromhex("4e05010202000000162b64fe3b004593")


def _families(cipher: TwoRoundAesCipher):
    base = _base_state()
    result = []
    for position in (8, 9, 10):
        samples = []
        for delta in (1, 2, 4, 8):
            variant = bytearray(base)
            variant[position] ^= delta
            variant[11] ^= delta
            samples.append((delta, cipher.encrypt_block(bytes(variant))))
        result.append(DifferentialFamily(position, tuple(samples)))
    return result


def test_recovers_master_key_from_thirteen_chosen_plaintexts():
    cipher = TwoRoundAesCipher(KEY, SBOX, RCON)
    families = _families(cipher)

    recovered = recover_master_key(
        sbox=SBOX,
        rcon=RCON,
        base_plaintext=_base_state(),
        base_ciphertext=cipher.encrypt_block(_base_state()),
        families=families,
        paired_position=11,
        paired_samples=families[0].samples,
    )

    assert recovered == KEY


class _FakeArcade:
    def __init__(self):
        self.cipher = TwoRoundAesCipher(KEY, SBOX, RCON)
        self.death_queries = 0
        self.winning_state = CryptographyAgent._pack_arcade_state(
            {
                "SIG": 0x4E,
                "WIN_SCORE": 10_000_000,
                "WIN_SECTOR": 9,
                "WIN_X": 18,
                "WIN_Y": 13,
                "WIN_RUNES": (0xC3, 0x7A, 0xB0, 0xAE),
                "DEFAULT_RUNES": (0x16, 0x2B, 0x64, 0xFE),
            },
            winning=True,
        )

    def fetch(self, url, **kwargs):
        payload = kwargs["json_data"]
        if url.endswith("/api/start"):
            body = {"ok": True, "session_id": "test-session", "lives": 16}
        elif url.endswith("/api/death"):
            assert payload["session_id"] == "test-session"
            self.death_queries += 1
            plaintext = bytes.fromhex(payload["state_hex"])
            body = {
                "ok": True,
                "ciphertext": self.cipher.encrypt(plaintext).hex(),
                "lives_remaining": 16 - self.death_queries,
            }
        elif url.endswith("/api/load"):
            assert payload["session_id"] == "test-session"
            ciphertext = bytes.fromhex(payload["ciphertext"])
            body = {
                "ok": True,
                "win": ciphertext == self.cipher.encrypt(self.winning_state),
            }
            if body["win"]:
                body["flag"] = FLAG
        else:
            raise AssertionError(f"unexpected URL: {url}")
        return SimpleNamespace(
            status_code=200,
            body_preview=json.dumps(body),
        )


def _write_source_fixtures(tmp_path):
    cipher_source = tmp_path / "crypto.py"
    cipher_source.write_text(
        "\n".join([
            f"B = {SBOX!r}",
            f"r_con = {RCON!r}",
            "class SnowCipher:",
            "    def encrypt_block(self, block):",
            "        while len(key_columns) < 12:",
            "            pass",
            "        s = self._ark(s, rk[2])",
        ])
    )
    app_source = tmp_path / "app.py"
    app_source.write_text(
        "\n".join([
            "STARTING_LIVES = 16",
            "SIG = 0x4e",
            "WIN_SCORE = 10_000_000",
            "WIN_SECTOR = 9",
            "WIN_X = 18",
            "WIN_Y = 13",
            "WIN_RUNES = (0xc3, 0x7a, 0xb0, 0xae)",
            "DEFAULT_RUNES = (0x16, 0x2b, 0x64, 0xfe)",
            "def track_seal(): pass",
            "def flags_seal(): pass",
            '@app.post("/api/start")',
            "def api_start(): pass",
            '@app.post("/api/death")',
            "def api_death(): pass",
            '@app.post("/api/load")',
            "def api_load(): pass",
        ])
    )
    return [str(cipher_source), str(app_source)]


def test_agent_detects_and_solves_two_round_save_oracle(tmp_path):
    server = _FakeArcade()
    agent = CryptographyAgent(http_tool=server)
    challenge = {
        "id": "ashbyte-test",
        "category": "crypto",
        "url": "http://127.0.0.1:5000",
        "files": _write_source_fixtures(tmp_path),
    }

    analysis = agent.analyze_challenge(challenge)
    result = agent.solve_challenge(challenge)

    assert "two_round_aes_differential" in analysis["detected_types"]
    assert result["status"] == "solved"
    assert result["flag"] == FLAG
    assert server.death_queries == 13
    assert result["artifacts"]["techniques"] == [
        "chosen_plaintext_differential",
        "two_round_aes_key_recovery",
        "encrypted_save_forgery",
    ]

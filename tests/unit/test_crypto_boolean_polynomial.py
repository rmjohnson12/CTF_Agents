"""Tests for source-backed Boolean-polynomial linearization."""

from hashlib import sha256

import pytest

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from agents.specialists.cryptography.crypto_agent import CryptographyAgent
from tools.crypto.boolean_polynomial import (
    BooleanPolynomialError,
    parse_sage_public_output,
    solve_affine_boolean_system,
)


POLYNOMIALS = [
    "x1^4 + x2^2 + 1",
    "x2^4 + x3^2",
    "x3^2 + x4^4 + 1",
    "x1^2 + x2^4 + 1",
    "x2^2 + x3^4",
]
SECRET = 21
FLAG = "HTB{boolean_linearization_regression}"


def _evaluate(polynomial: str, value: int) -> int:
    result = 0
    for term in polynomial.split(" + "):
        if term == "1":
            result ^= 1
        else:
            variable = int(term[1:].split("^", 1)[0]) - 1
            result ^= (value >> variable) & 1
    return result


def _output_text() -> str:
    encrypted_bits = [_evaluate(poly, SECRET) for poly in POLYNOMIALS]
    aes_key = sha256(str(SECRET).encode()).digest()
    ciphertext = AES.new(aes_key, AES.MODE_ECB).encrypt(
        pad(FLAG.encode(), 16)
    )
    return "\n".join([
        f"({', '.join(POLYNOMIALS)})",
        f"[{', '.join(str(bit) for bit in encrypted_bits)}]",
        ciphertext.hex(),
    ])


def _source_text() -> str:
    return "\n".join([
        "import hashlib",
        "from Crypto.Cipher import AES",
        "q = 2",
        "J = ideal([x^q-x for x in R.gens()])",
        "F = Q(F^(2*q)+F^q+1)",
        "msg = P.bits()",
        "N = 5",
        "AES_KEY = hashlib.sha256(str(KEY).encode()).digest()",
        "cipher = AES.new(AES_KEY, AES.MODE_ECB)",
    ])


def test_linearizes_and_enumerates_rank_deficient_system():
    polynomials, outputs, _ciphertext = parse_sage_public_output(_output_text())

    solutions = solve_affine_boolean_system(polynomials, outputs)

    assert solutions.rank == 3
    assert solutions.nullity == 2
    assert SECRET in set(solutions.integers())


def test_rejects_cross_terms_instead_of_mislinearizing_them():
    with pytest.raises(BooleanPolynomialError, match="unsupported"):
        solve_affine_boolean_system(["x1*x2"], [0])


def test_agent_recovers_aes_flag_from_sage_artifacts(tmp_path):
    source = tmp_path / "source.sage"
    source.write_text(_source_text())
    output = tmp_path / "output.txt"
    output.write_text(_output_text())
    challenge = {
        "id": "boolean-hfe-test",
        "category": "crypto",
        "files": [str(source), str(output)],
    }
    agent = CryptographyAgent()

    analysis = agent.analyze_challenge(challenge)
    result = agent.solve_challenge(challenge)

    assert "boolean_polynomial_linearization" in analysis["detected_types"]
    assert result["status"] == "solved"
    assert result["flag"] == FLAG
    assert result["artifacts"]["techniques"] == [
        "boolean_polynomial_linearization",
        "gf2_gaussian_elimination",
        "bounded_nullspace_enumeration",
    ]

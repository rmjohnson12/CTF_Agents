"""Cryptanalysis helpers for two-round AES-like CTF ciphers.

The supported construction is:

    AddRoundKey
    SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
    SubBytes -> ShiftRows -> MixColumns -> AddRoundKey

With chosen plaintexts that vary one byte per first-round MixColumns row, a
handful of differential pairs recovers the final linear whitening key. AES-128
key expansion is reversible, so that round key yields the master key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple


class TwoRoundAesRecoveryError(ValueError):
    """Raised when observations do not uniquely determine the key."""


@dataclass(frozen=True)
class DifferentialFamily:
    """Ciphertexts obtained by XORing ``delta`` into one plaintext byte."""

    position: int
    samples: Tuple[Tuple[int, bytes], ...]


class TwoRoundAesCipher:
    """Concrete form of the reduced AES-like construction used by the attack."""

    def __init__(self, key: bytes, sbox: Sequence[int], rcon: Sequence[int]):
        if len(key) != 16:
            raise ValueError("two-round AES key must contain 16 bytes")
        if len(sbox) != 256 or len(set(int(value) for value in sbox)) != 256:
            raise ValueError("S-box must be a 256-byte permutation")
        if len(rcon) < 3:
            raise ValueError("round constants must include entries 0, 1, and 2")
        self.key = bytes(key)
        self.sbox = tuple(int(value) & 0xFF for value in sbox)
        self.rcon = tuple(int(value) & 0xFF for value in rcon)

    @staticmethod
    def _xtime(value: int) -> int:
        return (((value << 1) ^ 0x1B) & 0xFF) if value & 0x80 else value << 1

    @staticmethod
    def _to_matrix(data: Sequence[int]) -> List[List[int]]:
        return [list(data[index:index + 4]) for index in range(0, len(data), 4)]

    @staticmethod
    def _from_matrix(matrix: Sequence[Sequence[int]]) -> bytes:
        return bytes(value for row in matrix for value in row)

    @classmethod
    def _mix_vector(cls, values: Sequence[int]) -> List[int]:
        column = list(values)
        total = column[0] ^ column[1] ^ column[2] ^ column[3]
        first = column[0]
        return [
            column[0] ^ total ^ cls._xtime(column[0] ^ column[1]),
            column[1] ^ total ^ cls._xtime(column[1] ^ column[2]),
            column[2] ^ total ^ cls._xtime(column[2] ^ column[3]),
            column[3] ^ total ^ cls._xtime(column[3] ^ first),
        ]

    @classmethod
    def mix_columns(cls, state: Sequence[Sequence[int]]) -> List[List[int]]:
        return [cls._mix_vector(row) for row in state]

    @classmethod
    def inverse_mix_columns(
        cls,
        state: Sequence[Sequence[int]],
    ) -> List[List[int]]:
        adjusted = [list(row) for row in state]
        for row in adjusted:
            even = cls._xtime(cls._xtime(row[0] ^ row[2]))
            odd = cls._xtime(cls._xtime(row[1] ^ row[3]))
            row[0] ^= even
            row[1] ^= odd
            row[2] ^= even
            row[3] ^= odd
        return cls.mix_columns(adjusted)

    @staticmethod
    def shift_rows(state: Sequence[Sequence[int]]) -> List[List[int]]:
        result = [list(row) for row in state]
        for column in range(1, 4):
            for row in range(4):
                result[row][column] = state[(row + column) % 4][column]
        return result

    @staticmethod
    def inverse_shift_rows(state: Sequence[Sequence[int]]) -> List[List[int]]:
        result = [list(row) for row in state]
        for column in range(1, 4):
            for row in range(4):
                result[row][column] = state[(row - column) % 4][column]
        return result

    @staticmethod
    def _add_round_key(
        state: Sequence[Sequence[int]],
        key: Sequence[Sequence[int]],
    ) -> List[List[int]]:
        return [
            [state[row][column] ^ key[row][column] for column in range(4)]
            for row in range(4)
        ]

    def expand_key(self) -> List[List[List[int]]]:
        words = self._to_matrix(self.key)
        iteration = 1
        while len(words) < 12:
            word = words[-1][:]
            if len(words) % 4 == 0:
                word.append(word.pop(0))
                word = [self.sbox[value] for value in word]
                word[0] ^= self.rcon[iteration]
                iteration += 1
            word = [
                left ^ right
                for left, right in zip(word, words[-4])
            ]
            words.append(word)
        return [words[4 * index:4 * (index + 1)] for index in range(3)]

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("block must contain 16 bytes")
        round_keys = self.expand_key()
        state = self._to_matrix(block)
        state = self._add_round_key(state, round_keys[0])
        for round_index in (1, 2):
            state = [[self.sbox[value] for value in row] for row in state]
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self._add_round_key(state, round_keys[round_index])
        return self._from_matrix(state)

    def encrypt(self, plaintext: bytes) -> bytes:
        padding = 16 - (len(plaintext) % 16)
        padded = plaintext + bytes([padding]) * padding
        return b"".join(
            self.encrypt_block(padded[index:index + 16])
            for index in range(0, len(padded), 16)
        )

    def final_linear_inverse(self, block: bytes) -> bytes:
        state = self._to_matrix(block)
        state = self.inverse_mix_columns(state)
        state = self.inverse_shift_rows(state)
        return self._from_matrix(state)


def _mixed_single_byte(
    cipher: TwoRoundAesCipher,
    column: int,
    difference: int,
) -> List[int]:
    vector = [0, 0, 0, 0]
    vector[column] = difference
    return cipher._mix_vector(vector)


def _recover_position(
    cipher: TwoRoundAesCipher,
    base_plaintext: bytes,
    base_linear: bytes,
    family: DifferentialFamily,
) -> Tuple[int, int, List[int]]:
    row, column = divmod(family.position, 4)
    output_row = (row - column) % 4
    observed = []
    for delta, ciphertext in family.samples:
        current = cipher.final_linear_inverse(ciphertext)
        observed.append((
            delta,
            [
                base_linear[output_row * 4 + index]
                ^ current[output_row * 4 + index]
                for index in range(4)
            ],
        ))

    candidates = []
    base_input = base_plaintext[family.position]
    for key_byte in range(256):
        differentials = []
        for delta, output_difference in observed:
            substituted = (
                cipher.sbox[base_input ^ key_byte]
                ^ cipher.sbox[(base_input ^ delta) ^ key_byte]
            )
            differentials.append((
                _mixed_single_byte(cipher, column, substituted),
                output_difference,
            ))

        base_values: List[List[int]] = []
        for output_column in range(4):
            matches = [
                base_value
                for base_value in range(256)
                if all(
                    (
                        cipher.sbox[base_value]
                        ^ cipher.sbox[
                            base_value ^ input_difference[output_column]
                        ]
                    )
                    == output_difference[output_column]
                    for input_difference, output_difference in differentials
                )
            ]
            if not matches:
                break
            base_values.append(matches)
        if len(base_values) == 4:
            candidates.append((key_byte, base_values))

    if len(candidates) != 1 or any(
        len(values) != 1 for values in candidates[0][1]
    ):
        raise TwoRoundAesRecoveryError(
            f"plaintext byte {family.position} produced "
            f"{len(candidates)} key candidates"
        )

    key_byte, values = candidates[0]
    base_u = [items[0] for items in values]
    linear_key_row = [
        base_linear[output_row * 4 + index] ^ cipher.sbox[base_u[index]]
        for index in range(4)
    ]
    return output_row, key_byte, linear_key_row


def _reverse_key_schedule(
    round_key_2: bytes,
    sbox: Sequence[int],
    rcon: Sequence[int],
) -> bytes:
    words: List[List[int] | None] = [None] * 12
    words[8:12] = TwoRoundAesCipher._to_matrix(round_key_2)
    for index in range(11, 3, -1):
        current = words[index]
        previous = words[index - 1]
        if current is None or previous is None:
            raise TwoRoundAesRecoveryError("round-key reversal lost a word")
        if index % 4 == 0:
            transformed = previous[:]
            transformed.append(transformed.pop(0))
            transformed = [sbox[value] for value in transformed]
            transformed[0] ^= rcon[index // 4]
            words[index - 4] = [
                left ^ right
                for left, right in zip(current, transformed)
            ]
        else:
            words[index - 4] = [
                left ^ right
                for left, right in zip(current, previous)
            ]
    return TwoRoundAesCipher._from_matrix(
        [word for word in words[:4] if word is not None]
    )


def recover_master_key(
    *,
    sbox: Sequence[int],
    rcon: Sequence[int],
    base_plaintext: bytes,
    base_ciphertext: bytes,
    families: Iterable[DifferentialFamily],
    paired_position: int,
    paired_samples: Tuple[Tuple[int, bytes], ...],
) -> bytes:
    """Recover the AES-128 master key from four isolated row differentials."""
    if len(base_plaintext) != 16 or len(base_ciphertext) != 16:
        raise ValueError("base plaintext and ciphertext must be one block")
    cipher = TwoRoundAesCipher(bytes(16), sbox, rcon)
    base_linear = cipher.final_linear_inverse(base_ciphertext)
    linear_key: List[int | None] = [None] * 16

    selected = list(families) + [
        DifferentialFamily(paired_position, paired_samples)
    ]
    for family in selected:
        output_row, _key_byte, row = _recover_position(
            cipher,
            base_plaintext,
            base_linear,
            family,
        )
        start = output_row * 4
        existing = linear_key[start:start + 4]
        if any(value is not None for value in existing) and existing != row:
            raise TwoRoundAesRecoveryError(
                f"inconsistent recovery for output row {output_row}"
            )
        linear_key[start:start + 4] = row

    if any(value is None for value in linear_key):
        raise TwoRoundAesRecoveryError("differentials did not cover all rows")

    linear_state = cipher._to_matrix(
        bytes(int(value) for value in linear_key)
    )
    round_key_2 = cipher._from_matrix(
        cipher.mix_columns(cipher.shift_rows(linear_state))
    )
    master_key = _reverse_key_schedule(round_key_2, sbox, rcon)
    verifier = TwoRoundAesCipher(master_key, sbox, rcon)
    if verifier.encrypt_block(base_plaintext) != base_ciphertext:
        raise TwoRoundAesRecoveryError("recovered key failed verification")
    return master_key

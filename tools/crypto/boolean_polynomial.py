"""Linearize and solve affine Boolean polynomial systems from CTF output.

For inputs in GF(2), every positive power of a variable is the same value:
``x**k == x``. Public keys that contain only sums of univariate monomials and
constants therefore reduce to ordinary affine systems over GF(2), even when
their printed degree looks high.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterator, List, Sequence, Tuple


class BooleanPolynomialError(ValueError):
    """Raised when an input is malformed or unsafe to enumerate."""


@dataclass(frozen=True)
class BooleanAffineSolutions:
    """A reduced affine system with a bounded family of bit-vector solutions."""

    variable_count: int
    rank: int
    pivot_columns: Tuple[int, ...]
    free_columns: Tuple[int, ...]
    reduced_rows: Tuple[int, ...]

    @property
    def nullity(self) -> int:
        return len(self.free_columns)

    def integers(self) -> Iterator[int]:
        """Yield solutions as little-endian integers, matching Sage ``bits()``."""
        rhs_column = self.variable_count
        for assignment in range(1 << self.nullity):
            bits = [0] * self.variable_count
            for index, column in enumerate(self.free_columns):
                bits[column] = (assignment >> index) & 1
            for row_index, column in enumerate(self.pivot_columns):
                row = self.reduced_rows[row_index]
                value = (row >> rhs_column) & 1
                for free_column in self.free_columns:
                    value ^= ((row >> free_column) & 1) * bits[free_column]
                bits[column] = value
            yield sum(bit << index for index, bit in enumerate(bits))


_MONOMIAL = re.compile(r"x([1-9]\d*)(?:\^([1-9]\d*))?")


def parse_sage_public_output(text: str) -> Tuple[List[str], List[int], bytes]:
    """Parse ``(polynomials)``, ``[bits]``, and a hex ciphertext."""
    lines = text.splitlines()
    if len(lines) != 3:
        raise BooleanPolynomialError("expected exactly three output lines")

    public_key = lines[0].strip()
    if not (public_key.startswith("(") and public_key.endswith(")")):
        raise BooleanPolynomialError("public key is not a polynomial tuple")
    polynomials = public_key[1:-1].split(", ")

    bit_vector = lines[1].strip()
    if not (bit_vector.startswith("[") and bit_vector.endswith("]")):
        raise BooleanPolynomialError("encrypted key is not a bit vector")
    raw_bits = bit_vector[1:-1]
    try:
        bits = [] if not raw_bits else [
            int(value) for value in raw_bits.split(", ")
        ]
    except ValueError as exc:
        raise BooleanPolynomialError("encrypted key contains a non-bit") from exc
    if any(bit not in (0, 1) for bit in bits):
        raise BooleanPolynomialError("encrypted key contains a non-bit")
    if len(polynomials) != len(bits) or not bits:
        raise BooleanPolynomialError(
            "public-key and encrypted-key dimensions do not match"
        )

    try:
        ciphertext = bytes.fromhex(lines[2].strip())
    except ValueError as exc:
        raise BooleanPolynomialError("ciphertext is not valid hexadecimal") from exc
    if not ciphertext or len(ciphertext) % 16:
        raise BooleanPolynomialError(
            "AES-ECB ciphertext must contain complete blocks"
        )
    return polynomials, bits, ciphertext


def _linearize(polynomial: str, variable_count: int) -> Tuple[int, int]:
    mask = 0
    constant = 0
    for term in polynomial.split(" + "):
        if term == "1":
            constant ^= 1
            continue
        match = _MONOMIAL.fullmatch(term)
        if not match:
            raise BooleanPolynomialError(
                f"unsupported Boolean polynomial term: {term[:80]}"
            )
        variable = int(match.group(1)) - 1
        if variable >= variable_count:
            raise BooleanPolynomialError(
                f"variable x{variable + 1} exceeds system dimension"
            )
        # Every positive power is x on a Boolean input. Repeated appearances
        # cancel because coefficients are in GF(2).
        mask ^= 1 << variable
    return mask, constant


def solve_affine_boolean_system(
    polynomials: Sequence[str],
    outputs: Sequence[int],
    *,
    max_nullity: int = 16,
) -> BooleanAffineSolutions:
    """Reduce a printed Boolean polynomial system with bit-packed elimination."""
    if len(polynomials) != len(outputs) or not outputs:
        raise BooleanPolynomialError("system dimensions do not match")
    if any(output not in (0, 1) for output in outputs):
        raise BooleanPolynomialError("system output contains a non-bit")

    variable_count = len(outputs)
    rows = []
    for polynomial, output in zip(polynomials, outputs):
        mask, constant = _linearize(polynomial, variable_count)
        rows.append(mask | ((output ^ constant) << variable_count))

    pivot_columns: List[int] = []
    pivot_row = 0
    for column in range(variable_count):
        selected = next(
            (
                row_index
                for row_index in range(pivot_row, len(rows))
                if (rows[row_index] >> column) & 1
            ),
            None,
        )
        if selected is None:
            continue
        rows[pivot_row], rows[selected] = rows[selected], rows[pivot_row]
        for row_index in range(len(rows)):
            if row_index != pivot_row and ((rows[row_index] >> column) & 1):
                rows[row_index] ^= rows[pivot_row]
        pivot_columns.append(column)
        pivot_row += 1

    coefficient_mask = (1 << variable_count) - 1
    for row in rows[pivot_row:]:
        if not (row & coefficient_mask) and ((row >> variable_count) & 1):
            raise BooleanPolynomialError("Boolean affine system is inconsistent")

    pivot_set = set(pivot_columns)
    free_columns = tuple(
        column
        for column in range(variable_count)
        if column not in pivot_set
    )
    if len(free_columns) > max_nullity:
        raise BooleanPolynomialError(
            f"system nullity {len(free_columns)} exceeds enumeration limit "
            f"{max_nullity}"
        )
    return BooleanAffineSolutions(
        variable_count=variable_count,
        rank=pivot_row,
        pivot_columns=tuple(pivot_columns),
        free_columns=free_columns,
        reduced_rows=tuple(rows[:pivot_row]),
    )

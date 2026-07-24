"""Unit tests for the MicroPython .mpy reverse-engineering playbook.

Covers the "Cinderbound" pattern: a .mpy bytecode module whose checker maps each
input byte through a position-local rolling transform and compares the result to
a constant table. The agent disassembles the bytecode (vendored mpy-tool.py),
reconstructs the transform, and inverts it to recover the accepted input.

The fixture is the real 221-byte challenge module, embedded as base64 so the
test is self-contained (no network, no git-ignored files). micropython is
optional — verification degrades to trusting the arithmetic inversion.
"""
import base64

import pytest

from agents.specialists.reverse_engineering.reverse_agent import ReverseEngineeringAgent

# Real cinderbound.mpy (MicroPython v6). judge("c1nd3rbound_v0w5") -> True.
_CINDERBOUND_MPY_B64 = (
    "TQYAHwgBGGp1ZGdlX3NyYy5weQAPCmp1ZGdlAHkQc3lsbGFibGUAgVeBb4FZChAHAjU3BwMxMjkH"
    "AzE1NAcCMzEHAzE5OQcDMTkyBwI3MwcDMjQzBwI0MwcDMTc2BwMyNTUHAzE3MwcCNTQHAzIwMwcC"
    "NjcHAjE1TAACATIAFgJRYwGFQFkUAgQgIyQjKjIuMCMAwSKAWsIrAMMSBbA0AYBCa1fEEgawtFU0"
    "AbLutI30IoF/7+7FshIGsLRVNAHyIoF/78KzFAO1NgFZgeVYWtdDEFlZsxIHsTQB2WM="
)


@pytest.fixture
def mpy_file(tmp_path):
    data = base64.b64decode(_CINDERBOUND_MPY_B64)
    assert data[:2] == b"M\x06", "fixture is not a MicroPython v6 .mpy"
    path = tmp_path / "cinderbound.mpy"
    path.write_bytes(data)
    return str(path)


def test_agent_solves_micropython_mpy_checker(mpy_file):
    agent = ReverseEngineeringAgent()
    steps = []
    result = agent._try_micropython_mpy(mpy_file, {"id": "cinderbound", "category": "reverse"}, steps)

    assert result is not None
    assert result["status"] == "solved"
    assert result["flag"] == "HTB{c1nd3rbound_v0w5}"
    assert result["artifacts"]["mpy_recovered_input"] == "c1nd3rbound_v0w5"
    # It should have reconstructed the transform, not just dumped strings.
    assert any("Reconstructed check" in s for s in steps)


def test_reverse_agent_ignores_non_mpy(tmp_path):
    agent = ReverseEngineeringAgent()
    other = tmp_path / "notmpy.bin"
    other.write_bytes(b"\x7fELF not micropython")
    assert agent._try_micropython_mpy(str(other), {"id": "x", "category": "reverse"}, []) is None


def test_invert_mpy_check_recovers_input_from_disassembly():
    # Directly exercise the inverter against the known target table, using a
    # minimal disassembly snippet in the exact shape mpy-tool emits.
    agent = ReverseEngineeringAgent()
    disasm = """
obj_table: [(57, 129, 154, 31, 199, 192, 73, 243, 43, 176, 255, 173, 54, 203, 67, 15)]
  22:80:5a    LOAD_CONST_SMALL_INT 90
  c2          STORE_FAST 2
  57          DUP_TOP
  c4          STORE_FAST 4
  12:06       LOAD_GLOBAL ord
  b0          LOAD_FAST 0
  b4          LOAD_FAST 4
  55          LOAD_SUBSCR
  34:01       CALL_FUNCTION 1
  b2          LOAD_FAST 2
  ee          BINARY_OP 23 __xor__
  b4          LOAD_FAST 4
  8d          LOAD_CONST_SMALL_INT 13
  f4          BINARY_OP 29 __mul__
  22:81:7f    LOAD_CONST_SMALL_INT 255
  ef          BINARY_OP 24 __and__
  ee          BINARY_OP 23 __xor__
  c5          STORE_FAST 5
  b2          LOAD_FAST 2
  12:06       LOAD_GLOBAL ord
  b0          LOAD_FAST 0
  b4          LOAD_FAST 4
  55          LOAD_SUBSCR
  34:01       CALL_FUNCTION 1
  f2          BINARY_OP 27 __add__
  22:81:7f    LOAD_CONST_SMALL_INT 255
  ef          BINARY_OP 24 __and__
  c2          STORE_FAST 2
  b3          LOAD_FAST 3
  14:03       LOAD_METHOD append
  b5          LOAD_FAST 5
  36:01       CALL_METHOD 1
  59          POP_TOP
  43:10       POP_JUMP_IF_TRUE -48
"""
    target = [57, 129, 154, 31, 199, 192, 73, 243, 43, 176, 255, 173, 54, 203, 67, 15]
    assert agent._invert_mpy_check(disasm, target, []) == "c1nd3rbound_v0w5"

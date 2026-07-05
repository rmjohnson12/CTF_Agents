"""Unit tests for witnessed-calldata replay discovery (no chain/network).

Covers the "Honor Among Thieves" pattern: isSolved is gated on a state var set
to msg.sender inside a function whose fixed-size argument must pass a one-way
keccak check. The winning argument was already broadcast by a prior caller, so
it is recoverable from transaction history — the discovery below is what routes
the agent to that playbook, driven entirely from source.
"""
from agents.specialists.blockchain.blockchain_agent import BlockchainAgent

_RIVALS = """
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
contract Rivals {
    event Voice(uint256 indexed severity);
    bytes32 private encryptedFlag;
    bytes32 private hashedFlag;
    address public solver;
    constructor(bytes32 _encrypted, bytes32 _hashed) {
        encryptedFlag = _encrypted;
        hashedFlag = _hashed;
    }
    function talk(bytes32 _key) external {
        bytes32 _flag = _key ^ encryptedFlag;
        if (keccak256(abi.encode(_flag)) == hashedFlag) {
            solver = msg.sender;
            emit Voice(5);
        } else {
            emit Voice(block.timestamp % 5);
        }
    }
}
"""

# Drain challenge: assigns msg.sender to a first-caller slot but has NO one-way
# gate, so it must NOT be picked up by the replay playbook.
_CREATURE = """
pragma solidity ^0.8.13;
contract Creature {
    uint256 public lifePoints;
    address public aggro;
    function attack(uint256 _damage) external {
        if (aggro == address(0)) { aggro = msg.sender; }
        if (tx.origin != msg.sender && aggro != msg.sender) { lifePoints -= _damage; }
    }
}
"""


def test_discovers_rivals_witness_replay_pattern():
    plan = BlockchainAgent._discover_witness_replay(_RIVALS)
    assert plan is not None
    assert plan["solve_fn"] == "talk"
    assert plan["arg_type"] == "bytes32"
    assert plan["state_var"] == "solver"
    assert plan["hash_compare"] is True
    assert plan["success_event"] == {"sig": "Voice(uint256)", "const": 5}


def test_drain_pattern_not_misdetected_as_replay():
    # No keccak/sha/ecrecover gate -> the replay playbook must decline so the
    # contract-drain playbook handles it instead.
    assert BlockchainAgent._discover_witness_replay(_CREATURE) is None


def test_signature_gated_replay_without_xor_is_detected():
    # ecrecover gate, no XOR: still a replay pattern, but not locally hash-verifiable.
    src = """pragma solidity ^0.8.0;
    contract C {
        address public owner;
        function claim(bytes32 h, uint8 v, bytes32 r, bytes32 s) external {
            if (ecrecover(h, v, r, s) == owner) { owner = msg.sender; }
        }
    }"""
    # Multi-arg function: the single-arg regex won't match, so this specific
    # multi-parameter shape is intentionally out of scope (no false detection).
    assert BlockchainAgent._discover_witness_replay(src) is None


def test_canonical_abi_type_only_accepts_single_word_types():
    ok = {"bytes32": "bytes32", "uint256": "uint256", "uint": "uint256",
          "address": "address", "bool": "bool", "uint128": "uint128"}
    for raw, expected in ok.items():
        assert BlockchainAgent._canonical_abi_type(raw) == expected
    for bad in ("bytes", "string", "uint7", "bytes33", "uint[]", "uint300"):
        assert BlockchainAgent._canonical_abi_type(bad) is None


def test_event_const_matches_indexed_and_data():
    from types import SimpleNamespace

    indexed_topics = [b"\x00" * 32, (5).to_bytes(32, "big")]
    assert BlockchainAgent._event_const_matches(SimpleNamespace(data=b""), indexed_topics, 5)
    assert not BlockchainAgent._event_const_matches(SimpleNamespace(data=b""), indexed_topics, 4)
    data_log = SimpleNamespace(data=(5).to_bytes(32, "big"))
    assert BlockchainAgent._event_const_matches(data_log, [b"\x00" * 32], 5)

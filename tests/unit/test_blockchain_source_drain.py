"""Unit tests for the source-driven contract-drain analysis (no chain/network).

Covers the "Distract and Destroy" pattern: damage gated on a contract caller
(tx.origin != msg.sender), a first-caller ("aggro") slot, and a loot/drain
function — all discovered from source rather than hard-coded.
"""
from agents.specialists.blockchain.blockchain_agent import BlockchainAgent

_CREATURE = """
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
contract Creature {
    uint256 public lifePoints;
    address public aggro;
    constructor() payable { lifePoints = 1000; }
    function attack(uint256 _damage) external {
        if (aggro == address(0)) { aggro = msg.sender; }
        if (_isOffBalance() && aggro != msg.sender) { lifePoints -= _damage; }
    }
    function loot() external {
        require(lifePoints == 0, "alive");
        payable(msg.sender).transfer(address(this).balance);
    }
    function _isOffBalance() private view returns (bool) { return tx.origin != msg.sender; }
}
"""


def test_discovers_members_from_source():
    m = BlockchainAgent._discover_drain_members(_CREATURE)
    assert m["damage_fn"] == "attack"
    assert m["drain_fn"] == "loot"
    assert m["health_var"] == "lifePoints"
    assert m["needs_first_caller"] is True
    assert m["needs_contract_caller"] is True


def test_solc_version_parsed_from_pragma():
    assert BlockchainAgent._solc_version(_CREATURE) == "0.8.13"
    assert BlockchainAgent._solc_version("pragma solidity 0.7.6;") == "0.7.6"
    assert BlockchainAgent._solc_version("no pragma here") == "0.8.13"  # safe default


def test_non_contract_caller_source_is_not_misdetected():
    src = """pragma solidity ^0.8.0;
    contract C { uint256 public hp; function hit(uint256 d) external { hp -= d; }
    function withdraw() external { payable(msg.sender).transfer(address(this).balance); } }"""
    m = BlockchainAgent._discover_drain_members(src)
    assert m["damage_fn"] == "hit"
    assert m["drain_fn"] == "withdraw"
    assert m["needs_contract_caller"] is False  # no tx.origin gate -> playbook won't engage

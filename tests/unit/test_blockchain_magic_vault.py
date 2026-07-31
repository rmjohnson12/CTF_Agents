"""Offline tests for the same-block Magic Vault entropy-mirror playbook."""

import solcx

from agents.specialists.blockchain.blockchain_agent import BlockchainAgent


VAULT_SOURCE = """
pragma solidity ^0.8.13;
contract Vault {
    struct Map { address holder; }
    Map map;
    address public owner;
    bytes32 private passphrase;
    uint256 public nonce;
    bool public isUnlocked;
    constructor() {
        owner = msg.sender;
        passphrase = bytes32(keccak256(abi.encodePacked(uint256(blockhash(block.timestamp)))));
        map = Map(address(this));
    }
    function mapHolder() public view returns (address) { return map.holder; }
    function claimContent() public { require(isUnlocked); map.holder = msg.sender; }
    function unlock(bytes16 _password) public { _magicPassword(); isUnlocked = true; }
    function _generateKey(uint256 r) private returns (uint256 ret) {
        ret = uint256(keccak256(abi.encodePacked(uint256(blockhash(block.number - r)) + nonce)));
        nonce++;
    }
    function _magicPassword() private returns (bytes8) {
        uint256 k1 = _generateKey(block.timestamp % 2 + 1);
        _generateKey(2);
        return bytes8(bytes32(k1));
    }
}
"""

SETUP_SOURCE = """
contract Setup {
    Vault public immutable TARGET;
    function isSolved() public view returns (bool) {
        return TARGET.mapHolder() != address(TARGET);
    }
}
"""


def test_detects_same_block_magic_vault_from_source():
    assert BlockchainAgent._is_same_block_magic_vault(VAULT_SOURCE + SETUP_SOURCE)


def test_rejects_generic_blockhash_contract_without_claim_lifecycle():
    source = "contract C { function value() external view returns(bytes32) { return blockhash(block.number - 1); } }"
    assert not BlockchainAgent._is_same_block_magic_vault(source)


def test_generated_helper_compiles_with_supported_solidity_version():
    version = "0.8.13"
    if version not in {str(item) for item in solcx.get_installed_solc_versions()}:
        return
    solcx.set_solc_version(version)
    compiled = solcx.compile_source(
        BlockchainAgent._same_block_magic_vault_solver_source(version),
        output_values=["abi", "bin"],
    )
    solver = next(value for key, value in compiled.items() if key.endswith(":MagicVaultSolver"))
    assert solver["bin"]


def test_magic_vault_playbook_is_integrated_before_generic_fallback(tmp_path, monkeypatch):
    vault = tmp_path / "Vault.sol"
    setup = tmp_path / "Setup.sol"
    vault.write_text(VAULT_SOURCE)
    setup.write_text(SETUP_SOURCE)
    agent = BlockchainAgent()
    monkeypatch.setattr(
        "agents.specialists.blockchain.blockchain_agent.assert_url_allowed",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(agent, "_find_host_port", lambda *_args: None)
    monkeypatch.setattr(agent, "_try_witnessed_calldata_replay", lambda **_kwargs: None)
    monkeypatch.setattr(agent, "_try_erc20_underflow_purchase", lambda **_kwargs: None)
    monkeypatch.setattr(
        agent,
        "_try_same_block_magic_vault",
        lambda **_kwargs: "HTB{magic_vault_fixture}",
    )

    result = agent.solve_challenge({
        "id": "magic-vault",
        "category": "blockchain",
        "description": "Open the magic vault.",
        "files": [str(vault), str(setup)],
        "connection_info": {
            "rpc_url": "http://127.0.0.1:8545/rpc",
            "flag_url": "http://127.0.0.1:8545/flag",
            "private_key": "0x" + "11" * 32,
            "attacker_address": "0x" + "22" * 20,
            "target_address": "0x" + "33" * 20,
            "setup_address": "0x" + "44" * 20,
        },
    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{magic_vault_fixture}"
    assert "same_block_entropy_mirroring" in result["techniques"]
    assert result["artifacts"]["same_block_entropy_mirror"] == {
        "transactions_bounded": 1,
        "captured_sensitive_values": False,
    }

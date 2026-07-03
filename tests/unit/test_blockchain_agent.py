from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, patch
from pathlib import Path
from agents.specialists.blockchain.blockchain_agent import BlockchainAgent
from core.utils.security import SecurityPolicyError
from tools.common.result import ToolResult


def test_blockchain_agent_capabilities():
    agent = BlockchainAgent()
    assert "blockchain" in agent.get_capabilities()
    assert "smart_contracts" in agent.get_capabilities()


def test_blockchain_agent_analysis():
    agent = BlockchainAgent()
    
    # Test case 1: explicitly blockchain category and solidity files
    challenge_1 = {
        "id": "blockchain_test",
        "category": "blockchain",
        "description": "Solve this smart contract challenge.",
        "files": ["Setup.sol", "Creature.sol"]
    }
    analysis = agent.analyze_challenge(challenge_1)
    assert analysis["can_handle"] is True
    assert analysis["confidence"] == 0.95
    assert "solidity_files" in analysis["detected_types"]

    # Test case 2: no explicit category, but blockchain terms
    challenge_2 = {
        "id": "misc_test",
        "category": "misc",
        "description": "Interact with our ganache RPC endpoint using your private key.",
        "files": []
    }
    analysis_2 = agent.analyze_challenge(challenge_2)
    assert analysis_2["can_handle"] is True
    assert analysis_2["confidence"] == 0.95
    assert "blockchain_terms" in analysis_2["detected_types"]


def test_blockchain_agent_solve_fallback(monkeypatch, tmp_path):
    setup_file = tmp_path / "Setup.sol"
    setup_file.write_text("contract Setup {}")
    
    agent = BlockchainAgent()
    agent.reasoner = MagicMock()
    agent.reasoner.is_available = False  # Trigger fallback path
    
    # Mock python tool execution
    mock_run = MagicMock()
    mock_run.return_value = ToolResult(
        argv=["python", "script.py"],
        stdout="Found flag: HTB{g0t_y0u2_f1r5t_b100d}",
        stderr="",
        exit_code=0,
        timed_out=False,
        duration_s=0.5
    )
    agent.python_tool.run = mock_run

    challenge = {
        "id": "survival",
        "category": "blockchain",
        "description": "Spawn instance at 127.0.0.1:30125. PrivateKey: 0x496cfcd90b30c64aa09ea4efd48f997041812dab612a01151f046679eb0774f5.",
        "files": [str(setup_file)]
    }

    result = agent.solve_challenge(challenge)
    
    assert result["status"] == "solved"
    assert result["flag"] == "HTB{g0t_y0u2_f1r5t_b100d}"
    assert any("Found target host: 127.0.0.1:30125" in step for step in result["steps"])
    assert any("Executing exploit script" in step for step in result["steps"])
    assert "generated_script" not in result["artifacts"]
    assert result["artifacts"]["generated_script_redacted"] is True
    
    # Check that python tool was indeed called
    assert mock_run.call_count == 1


def test_blockchain_agent_uses_structured_connection_info_without_host_port(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_AGENTS_ALLOWED_NETWORKS", "chain.local")
    setup_file = tmp_path / "Setup.sol"
    setup_file.write_text("contract Setup {}")

    agent = BlockchainAgent()
    agent.reasoner = MagicMock()
    agent.reasoner.is_available = False
    agent._get_connection_info = MagicMock(side_effect=AssertionError("network fetch should not run"))

    mock_run = MagicMock()
    mock_run.return_value = ToolResult(
        argv=["python", "script.py"],
        stdout="Found flag: HTB{structured_metadata}",
        stderr="",
        exit_code=0,
        timed_out=False,
        duration_s=0.5,
    )
    agent.python_tool.run = mock_run

    challenge = {
        "id": "structured_blockchain",
        "category": "blockchain",
        "description": "Exploit this Solidity smart contract.",
        "connection_info": {
            "rpc_url": "http://chain.local/rpc",
            "flag_url": "http://chain.local/flag",
            "private_key": "0x" + "11" * 32,
            "address": "0x" + "22" * 20,
            "target_address": "0x" + "33" * 20,
            "setup_address": "0x" + "44" * 20,
        },
        "files": [str(setup_file)],
    }

    result = agent.solve_challenge(challenge)

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{structured_metadata}"
    generated = mock_run.call_args.args[0]
    assert 'RPC_URL = "http://chain.local/rpc"' in generated
    assert 'requests.get("http://chain.local/flag")' in generated
    assert "generated_script" not in result["artifacts"]


def test_blockchain_connection_info_blocks_non_allowlisted_host(monkeypatch):
    monkeypatch.setenv("CTF_AGENTS_ALLOWED_NETWORKS", "localhost")
    agent = BlockchainAgent()

    try:
        agent._get_connection_info("203.0.113.10", 31337)
        assert False, "expected SecurityPolicyError"
    except SecurityPolicyError:
        assert True


def test_blockchain_agent_does_not_treat_private_key_prefix_as_address():
    agent = BlockchainAgent()
    info = agent._heuristically_extract_conn_info({
        "description": "PrivateKey: 0x" + "ab" * 32,
    })

    assert info["PrivateKey"] == "0x" + "ab" * 32
    assert "Address" not in info


def test_blockchain_agent_executes_bounded_creature_lifecycle(monkeypatch):
    monkeypatch.setenv("CTF_AGENTS_ALLOWED_NETWORKS", "127.0.0.1/32")
    creature = MagicMock()
    creature.functions.lifePoints.return_value.call.side_effect = [20, 0]
    creature.functions.strongAttack.return_value.build_transaction.return_value = {"attack": True}
    creature.functions.loot.return_value.build_transaction.return_value = {"loot": True}
    setup = MagicMock()
    setup.functions.isSolved.return_value.call.return_value = True

    web3 = MagicMock()
    web3.is_connected.return_value = True
    web3.eth.contract.side_effect = [creature, setup]
    web3.eth.get_balance.return_value = 10
    web3.eth.get_transaction_count.return_value = 0
    web3.eth.gas_price = 1
    web3.eth.chain_id = 31337
    web3.eth.account.sign_transaction.return_value = SimpleNamespace(raw_transaction=b"signed")
    web3.eth.send_raw_transaction.return_value = b"hash"
    web3.eth.wait_for_transaction_receipt.return_value = SimpleNamespace(status=1)

    web3_class = MagicMock(return_value=web3)
    web3_class.HTTPProvider.return_value = object()
    web3_class.to_checksum_address.side_effect = lambda value: value
    module = ModuleType("web3")
    module.Web3 = web3_class
    response = SimpleNamespace(status_code=200, text="HTB{bounded_creature_path}")
    agent = BlockchainAgent()
    steps = []

    with patch.dict("sys.modules", {"web3": module}), patch("requests.get", return_value=response):
        flag = agent._try_creature_lifecycle(
            rpc_url="http://127.0.0.1:31337/rpc",
            private_key="0x" + "11" * 32,
            attacker_address="0x" + "22" * 20,
            target_address="0x" + "33" * 20,
            setup_address="0x" + "44" * 20,
            flag_url="http://127.0.0.1:31337/flag",
            steps=steps,
            evidence_text="A warrior faces a monster creature.",
        )

    assert flag == "HTB{bounded_creature_path}"
    assert web3.eth.send_raw_transaction.call_count == 2
    assert any("Setup.isSolved() returned true" in step for step in steps)

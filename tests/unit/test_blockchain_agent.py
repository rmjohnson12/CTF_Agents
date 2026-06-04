from unittest.mock import MagicMock
from pathlib import Path
from agents.specialists.blockchain.blockchain_agent import BlockchainAgent
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
    
    # Check that python tool was indeed called
    assert mock_run.call_count == 1


def test_blockchain_agent_uses_structured_connection_info_without_host_port(monkeypatch, tmp_path):
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


def test_blockchain_agent_does_not_treat_private_key_prefix_as_address():
    agent = BlockchainAgent()
    info = agent._heuristically_extract_conn_info({
        "description": "PrivateKey: 0x" + "ab" * 32,
    })

    assert info["PrivateKey"] == "0x" + "ab" * 32
    assert "Address" not in info

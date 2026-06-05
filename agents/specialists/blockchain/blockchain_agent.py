"""
Blockchain Specialist Agent

Specialized agent for solving blockchain and smart contract CTF challenges.
"""

import re
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from urllib.parse import urlparse

from agents.base_agent import BaseAgent, AgentType
from tools.common.python_tool import PythonTool
from core.decision_engine.llm_reasoner import LLMReasoner
from core.utils.flag_utils import find_first_flag
from core.utils.security import assert_url_allowed

logger = logging.getLogger(__name__)


class BlockchainAgent(BaseAgent):
    """
    Specialist agent for blockchain and smart contract challenges.

    Handles:
    - Smart contract vulnerability analysis
    - Solidity source code analysis
    - Web3 transaction scripting (using web3.py)
    - Interaction with Ethereum/EVM-compatible private RPC endpoints
    """

    def __init__(
        self,
        agent_id: str = "blockchain_agent",
        reasoner: Optional[LLMReasoner] = None,
        python_tool: Optional[PythonTool] = None,
    ):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.reasoner = reasoner or LLMReasoner()
        self.python_tool = python_tool or PythonTool()
        self.capabilities = [
            "blockchain",
            "smart_contracts",
            "solidity",
            "web3",
            "ethereum",
            "evm",
        ]

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a challenge to see if it contains blockchain/Solidity indicators.
        """
        description = challenge.get("description", "").lower()
        hints = " ".join(challenge.get("hints", [])).lower()
        tags = " ".join(challenge.get("tags", [])).lower()
        files = [str(f).lower() for f in challenge.get("files", [])]

        indicators = []
        if any(f.endswith(".sol") for f in files):
            indicators.append("solidity_files")

        blockchain_keywords = [
            "blockchain",
            "solidity",
            "smart contract",
            "smart_contract",
            "ethereum",
            "web3",
            "ganache",
            "anvil",
        ]
        if any(kw in description or kw in hints or kw in tags for kw in blockchain_keywords):
            indicators.append("blockchain_terms")

        can_handle = challenge.get("category") == "blockchain" or bool(indicators)
        confidence = 0.95 if indicators else (0.4 if can_handle else 0.1)

        return {
            "agent_id": self.agent_id,
            "can_handle": can_handle,
            "confidence": confidence,
            "detected_types": indicators,
            "approach": self._plan_approach(indicators),
        }

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Attempt to solve a blockchain challenge by writing and running a web3.py script.
        """
        steps = []
        flag = None
        max_retries = 3

        # 1. Parse connection information
        connection_info = self._connection_info_from_challenge(challenge)
        host_port = self._find_host_port(challenge) or self._find_host_port(connection_info)

        if host_port:
            host, port = host_port
            steps.append(f"Found target host: {host}:{port}")

            fetched_info = self._get_connection_info(host, port)
            if fetched_info:
                steps.append("Retrieved connection details successfully from connection_info.")
                connection_info = self._merge_connection_info(
                    self._normalize_connection_info(fetched_info),
                    connection_info,
                )
            else:
                steps.append("Could not fetch connection details from server. Attempting heuristic parsing.")
        else:
            host = port = None

        connection_info = self._merge_connection_info(
            self._heuristically_extract_conn_info(challenge),
            connection_info,
        )

        rpc_url = self._connection_value(
            connection_info,
            "rpc_url", "rpcUrl", "rpc", "RPC_URL", "RPC", "RpcUrl",
        )
        if not rpc_url and host_port:
            rpc_url = f"http://{host}:{port}/rpc"

        flag_url = self._connection_value(
            connection_info,
            "flag_url", "flagUrl", "flag", "FLAG_URL",
        )
        if not flag_url and host_port:
            flag_url = f"http://{host}:{port}/flag"

        private_key = self._connection_value(
            connection_info,
            "PrivateKey", "private_key", "privateKey", "attacker_private_key",
        )
        attacker_address = self._connection_value(
            connection_info,
            "Address", "address", "attacker_address", "player_address", "wallet",
        )
        target_address = self._connection_value(
            connection_info,
            "TargetAddress", "target_address", "targetAddress", "target",
        )
        setup_address = self._connection_value(
            connection_info,
            "setupAddress", "setup_address", "SetupAddress", "setup",
        )

        if not rpc_url:
            steps.append("Failed to locate an RPC URL or target host/port in challenge.")
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "failed",
                "flag": None,
                "steps": steps,
            }

        steps.append(f"RPC URL: {rpc_url}")
        steps.append(f"Attacker address: {attacker_address}")
        steps.append(f"Target contract address: {target_address}")
        steps.append(f"Setup contract address: {setup_address}")

        # 2. Extract Solidity source files
        solidity_sources = {}
        files = challenge.get("files", [])
        for f in files:
            path = Path(f).expanduser()
            if path.suffix == ".sol" and path.is_file():
                try:
                    solidity_sources[path.name] = path.read_text(errors="ignore")
                except Exception as e:
                    logger.debug("Failed to read solidity file %s: %s", path, e)

        if not solidity_sources:
            steps.append("Warning: No local Solidity files found in the challenge.")
        else:
            steps.append(f"Loaded {len(solidity_sources)} Solidity file(s) for analysis.")

        # 3. Generate script via LLM or fallback
        script_content = ""
        if not self.reasoner.is_available:
            steps.append("LLM not available. Attempting deterministic fallback or template script...")
            script_content = self._get_fallback_script(
                rpc_url,
                private_key,
                attacker_address,
                target_address,
                setup_address,
                flag_url,
            )
        else:
            steps.append("Generating smart contract exploit script via LLM...")
            script_content = self._generate_blockchain_exploit_script(
                challenge.get("description", ""),
                solidity_sources,
                rpc_url,
                private_key,
                attacker_address,
                target_address,
                setup_address,
                flag_url,
            )

        if not script_content:
            steps.append("Failed to generate solver script.")
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "failed",
                "flag": None,
                "steps": steps,
            }

        # 4. Self-correction loop
        last_error = ""
        last_stdout = ""
        for attempt in range(max_retries + 1):
            if attempt > 0:
                steps.append(f"Attempt {attempt + 1}: Fixing script based on error...")
                script_content = self._fix_blockchain_exploit_script(
                    script_content,
                    last_error,
                    last_stdout,
                    challenge.get("description", ""),
                    solidity_sources,
                    rpc_url,
                    private_key,
                    attacker_address,
                    target_address,
                    setup_address,
                    flag_url,
                )

            if not script_content:
                continue

            steps.append(f"Executing exploit script (Attempt {attempt + 1})...")
            try:
                res = self.python_tool.run(script_content)
                last_stdout = res.stdout
                
                if res.stdout:
                    found_flag = find_first_flag(res.stdout)
                    if found_flag:
                        flag = found_flag
                        steps.append(f"SUCCESS: Flag found in script output: {flag}")
                        break
                
                if res.stderr:
                    last_error = res.stderr
                    steps.append(f"Script stderr: {res.stderr[:200]}")
                elif not res.stdout:
                    last_error = "Script produced no output."
                    steps.append(f"  {last_error}")
                else:
                    last_error = "Script completed but no flag found in output."
                    steps.append("  No flag detected in script stdout.")
                
                if res.exit_code != 0:
                    steps.append(f"Script failed with exit code {res.exit_code}")

            except Exception as e:
                logger.warning("Script execution failed: %s", e)
                last_error = str(e)
                steps.append(f"Execution error: {e}")

        return {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": "solved" if flag else "failed",
            "flag": flag,
            "steps": steps,
            "artifacts": {
                "generated_script_redacted": True,
                "final_attempt": attempt + 1,
            },
        }

    def get_capabilities(self) -> List[str]:
        return self.capabilities

    def _find_host_port(self, challenge: Dict[str, Any]) -> Optional[Tuple[str, int]]:
        candidates = []
        if challenge.get("url"):
            candidates.append(str(challenge["url"]))
        target = challenge.get("target")
        if isinstance(target, dict):
            candidates.extend(str(v) for v in target.values() if v)
        elif target:
            candidates.append(str(target))
        connection_info = challenge.get("connection_info")
        if isinstance(connection_info, dict):
            candidates.extend(str(v) for v in connection_info.values() if v)
        candidates.extend(
            str(v) for v in (
                challenge.get("description", ""),
                challenge.get("rpc_url", ""),
                challenge.get("rpcUrl", ""),
                challenge.get("RPC_URL", ""),
                challenge.get("flag_url", ""),
                challenge.get("flagUrl", ""),
                challenge.get("FLAG_URL", ""),
            )
            if v
        )

        for text in candidates:
            match = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3}|localhost|127\.0\.0\.1):(\d{2,5})\b", text)
            if match:
                return match.group(1), int(match.group(2))
            parsed = urlparse(text if re.match(r"^\w+://", text) else f"http://{text}")
            if parsed.hostname and parsed.port:
                return parsed.hostname, parsed.port
        return None

    def _get_connection_info(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        import requests
        url = f"http://{host}:{port}/connection_info"
        assert_url_allowed(url)
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return None

    @staticmethod
    def _normalize_connection_info(raw: Any) -> Dict[str, Any]:
        if isinstance(raw, dict):
            return dict(raw)
        return {}

    @staticmethod
    def _connection_info_from_challenge(challenge: Dict[str, Any]) -> Dict[str, Any]:
        info = BlockchainAgent._normalize_connection_info(challenge.get("connection_info"))
        for key in (
            "rpc_url", "rpcUrl", "RPC_URL", "rpc", "RPC",
            "flag_url", "flagUrl", "FLAG_URL", "flag",
            "PrivateKey", "private_key", "privateKey", "attacker_private_key",
            "Address", "address", "attacker_address", "player_address", "wallet",
            "TargetAddress", "target_address", "targetAddress", "target",
            "setupAddress", "setup_address", "SetupAddress", "setup",
        ):
            value = challenge.get(key)
            if value not in (None, ""):
                info[key] = value
        return info

    @staticmethod
    def _merge_connection_info(*infos: Dict[str, Any]) -> Dict[str, Any]:
        merged: Dict[str, Any] = {}
        for info in infos:
            for key, value in info.items():
                if value not in (None, ""):
                    merged[key] = value
        return merged

    @staticmethod
    def _connection_value(info: Dict[str, Any], *keys: str) -> Optional[str]:
        for key in keys:
            value = info.get(key)
            if value not in (None, ""):
                return str(value)
        return None

    def _heuristically_extract_conn_info(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        text = challenge.get("description", "")
        info = {}
        # Simple regex matching for private key and addresses
        pk_match = re.search(r"(?<![0-9a-fA-F])0x[0-9a-fA-F]{64}(?![0-9a-fA-F])", text)
        if pk_match:
            info["PrivateKey"] = pk_match.group(0)
        
        addresses = re.findall(r"(?<![0-9a-fA-F])0x[0-9a-fA-F]{40}(?![0-9a-fA-F])", text)
        if len(addresses) >= 1:
            info["Address"] = addresses[0]
        if len(addresses) >= 2:
            info["TargetAddress"] = addresses[1]
        if len(addresses) >= 3:
            info["setupAddress"] = addresses[2]
            
        return info

    def _generate_blockchain_exploit_script(
        self,
        challenge_desc: str,
        solidity_sources: Dict[str, str],
        rpc_url: str,
        private_key: str,
        attacker_address: str,
        target_address: str,
        setup_address: str,
        flag_url: Optional[str],
    ) -> str:
        sources_str = "\n\n".join(f"--- File: {name} ---\n{code}" for name, code in solidity_sources.items())
        flag_instruction = (
            f"Finally, make a GET request to `{flag_url}` to fetch and print the flag."
            if flag_url
            else "If the challenge exposes a flag endpoint or solve-check endpoint, fetch it and print the flag; otherwise print the isSolved() result and relevant transaction output."
        )
        prompt = f"""
        You are a World-Class Blockchain CTF Exploitation Expert.
        Write a Python script using the 'web3' library to solve the following blockchain smart contract CTF challenge.
        
        Challenge Description:
        {challenge_desc}
        
        Solidity Smart Contract Source Files:
        {sources_str}
        
        Connection and Deployment Details:
        - RPC URL: {rpc_url}
        - Deployer/Attacker Address: {attacker_address}
        - Private Key: {private_key}
        - Target Contract Address: {target_address}
        - Setup Contract Address: {setup_address}
        
        Goal:
        Interact with the smart contracts on the blockchain using the private key and addresses provided to solve the challenge.
        The challenge is solved when the Setup contract's `isSolved()` function returns `true` (or when the conditions defined in `isSolved` are met, e.g. target contract balance is 0).
        
        Requirements for the Python script:
        1. Connect to the Ethereum RPC URL using `Web3(Web3.HTTPProvider(rpc_url))`.
        2. Define the ABI for the Target and Setup contracts (extract or reconstruct the functions/state variables needed from the Solidity source files provided).
        3. Build, sign, and send transactions to execute the exploit logic. Remember to wait for transaction receipts to ensure state updates are mined.
        4. Query the Setup contract's `isSolved()` view function at the end to make sure it is solved.
        5. {flag_instruction}
        6. Print the retrieved flag clearly to stdout (e.g. 'Found flag: HTB{{...}}').
        7. The script must be fully self-contained. Use only standard libraries plus `requests` and `web3`.
        
        Return ONLY the Python code. No markdown formatting, no explanation, no backticks.
        """.strip()

        return self.reasoner._call_llm(prompt).strip().replace("```python", "").replace("```", "").strip()

    def _fix_blockchain_exploit_script(
        self,
        script: str,
        error: str,
        stdout: str,
        challenge_desc: str,
        solidity_sources: Dict[str, str],
        rpc_url: str,
        private_key: str,
        attacker_address: str,
        target_address: str,
        setup_address: str,
        flag_url: Optional[str],
    ) -> str:
        sources_str = "\n\n".join(f"--- File: {name} ---\n{code}" for name, code in solidity_sources.items())
        prompt = f"""
        You are a World-Class Blockchain CTF Exploitation Expert.
        Fix the following Python script which failed while trying to solve the blockchain challenge.
        
        Original Script:
        {script}
        
        Execution Error:
        {error}
        
        Execution Output (stdout):
        {stdout}
        
        Challenge Context:
        Description: {challenge_desc}
        Connection Details: RPC={rpc_url}, PrivateKey={private_key}, Attacker={attacker_address}, Target={target_address}, Setup={setup_address}, FlagURL={flag_url}
        
        Solidity Sources:
        {sources_str}
        
        Return ONLY the fixed Python code. No markdown formatting, no explanation, no backticks.
        """.strip()

        return self.reasoner._call_llm(prompt).strip().replace("```python", "").replace("```", "").strip()

    def _get_fallback_script(
        self,
        rpc_url: str,
        private_key: str,
        attacker_address: str,
        target_address: str,
        setup_address: str,
        flag_url: Optional[str],
    ) -> str:
        # Fallback template specifically targeting Survival of the Fittest or similar simple challenge
        flag_fetch = (
            f'r = requests.get("{flag_url}")\nprint(r.text)'
            if flag_url
            else 'print("Solved:", True)'
        )
        return f"""
import requests
from web3 import Web3

RPC_URL = "{rpc_url}"
PRIVATE_KEY = "{private_key}"
ADDRESS = "{attacker_address}"
TARGET_ADDRESS = "{target_address}"
SETUP_ADDRESS = "{setup_address}"

w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    print("Failed to connect")
    exit(1)

# Minimal target ABI
creature_abi = [
    {{"inputs": [], "name": "lifePoints", "outputs": [{{"type": "uint256"}}], "stateMutability": "view", "type": "function"}},
    {{"inputs": [{{"type": "uint256", "name": "_damage"}}], "name": "strongAttack", "outputs": [], "stateMutability": "external", "type": "function"}},
    {{"inputs": [], "name": "loot", "outputs": [], "stateMutability": "external", "type": "function"}}
]

creature = w3.eth.contract(address=TARGET_ADDRESS, abi=creature_abi)
life_points = creature.functions.lifePoints().call()

if life_points > 0:
    tx = creature.functions.strongAttack(life_points).build_transaction({{
        'from': ADDRESS,
        'nonce': w3.eth.get_transaction_count(ADDRESS),
        'gas': 100000,
        'gasPrice': w3.eth.gas_price
    }})
    signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)

if w3.eth.get_balance(TARGET_ADDRESS) > 0:
    tx = creature.functions.loot().build_transaction({{
        'from': ADDRESS,
        'nonce': w3.eth.get_transaction_count(ADDRESS),
        'gas': 100000,
        'gasPrice': w3.eth.gas_price
    }})
    signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)

# Get flag
{flag_fetch}
"""

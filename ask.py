import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional

# Ensure we can import from project root
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.specialists.cryptography.crypto_agent import CryptographyAgent
from agents.specialists.web_exploitation.web_agent import WebExploitationAgent
from agents.specialists.misc.coding_agent import CodingAgent
from agents.specialists.forensics.forensics_agent import ForensicsAgent
from agents.specialists.reverse_engineering.reverse_agent import ReverseEngineeringAgent
from agents.specialists.osint.osint_agent import OSINTAgent
from agents.specialists.log_analysis.log_agent import LogAnalysisAgent
from core.decision_engine.llm_reasoner import LLMReasoner

def _extract_referenced_paths(user_input: str) -> List[str]:
    potential_paths = [
        w.strip(" \"',?!.;")
        for w in user_input.split()
        if "/" in w or w.startswith("~")
    ]
    files_in_prompt = []
    for p in potential_paths:
        full_path = os.path.expanduser(p)
        if os.path.exists(full_path):
            files_in_prompt.append(full_path)

    current_files = [
        f
        for f in os.listdir(".")
        if os.path.isfile(f) and f.lower() in user_input.lower()
    ]
    files_in_prompt.extend([os.path.abspath(f) for f in current_files])
    return sorted(set(files_in_prompt))

def _load_challenge_json(path: str) -> Optional[Dict[str, Any]]:
    if not path.lower().endswith(".json"):
        return None

    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    if not isinstance(data, dict):
        return None

    if not any(key in data for key in ("description", "category", "name")):
        return None

    return data

def _heuristic_challenge_from_instruction(
    user_input: str,
    available_tools: List[str],
) -> Dict[str, Any]:
    files_in_prompt = _extract_referenced_paths(user_input)

    challenge_jsons = [
        loaded
        for path in files_in_prompt
        if (loaded := _load_challenge_json(path)) is not None
    ]
    if len(challenge_jsons) == 1:
        challenge = challenge_jsons[0]
        metadata = dict(challenge.get("metadata") or {})
        metadata.setdefault("system_tools", available_tools)
        challenge["metadata"] = metadata
        return challenge

    category = "misc"
    url = None
    url_match = re.search(r'https?://[^\s<>"]+|www\.[^\s<>"]+', user_input)
    if url_match:
        url = url_match.group(0).strip(".,")

    lowered_input = user_input.lower()
    crypto_terms = [
        "decrypt",
        "decode",
        "encoded",
        "cipher",
        "hash",
        "md5",
        "sha",
        "base64",
        "hex",
        "password",
        "rockyou",
    ]

    challenge_files = [
        path for path in files_in_prompt
        if _load_challenge_json(path) is None
    ]

    forensics_terms = ["hidden", "artifact", "forensics", "extract", "embedded", "strings"]

    log_terms = ["log", "auth", "ssh", "brute force", "failed password", "authentication"]
    coding_terms = ["calculate", "sum", "prime", "algorithm", "program", "script", "format ctf"]

    if any(term in lowered_input for term in log_terms):
        category = "log"
    elif (
        any(f.endswith('.pdf') or f.endswith('.pcap') or f.endswith('.pcapng') for f in challenge_files)
        or (
            any(f.endswith('.bin') or f.endswith('.dat') for f in challenge_files)
            and any(term in lowered_input for term in forensics_terms)
        )
    ):
        category = "forensics"
    elif any(f.endswith('.py') or f.endswith('.exe') for f in challenge_files) or "authenticate" in lowered_input:
        category = "reverse"
    elif url or ".cloud" in lowered_input:
        category = "web"
    elif any(f.endswith('.txt') for f in challenge_files) or any(term in lowered_input for term in crypto_terms):
        category = "crypto"
    elif any(term in lowered_input for term in coding_terms):
        category = "misc"

    return {
        "id": "heuristic_task",
        "name": "Heuristic Task",
        "category": category,
        "description": user_input,
        "files": challenge_files,
        "url": url,
        "metadata": {"system_tools": available_tools}
    }

def main():
    if len(sys.argv) < 2:
        print("Usage: python ask.py \"your instruction here\"")
        sys.exit(1)

    user_input = " ".join(sys.argv[1:])
    print(f"\n--- Processing Instruction: \"{user_input}\" ---")

    reasoner = LLMReasoner()
    
    # Step 1: Use LLM to convert natural language to challenge JSON
    from core.utils.system_checks import get_available_tools, get_system_context
    available_tools = get_available_tools()
    system_ctx = get_system_context()

    prompt = f"""
Convert the following natural language security instruction into a standard CTF challenge JSON object.
Instruction: {user_input}

Current working directory: {os.getcwd()}
Available files in directory: {', '.join([f for f in os.listdir('.') if os.path.isfile(f)])}
{system_ctx}

Return ONLY the JSON object.
Example shape:
{{
  "id": "transient_task",
  "name": "Manual Task",
  "category": "forensics|web|crypto|misc",
  "description": "...",
  "files": ["path/to/file"],
  "url": "..."
}}
"""
    
    try:
        if reasoner.client is None:
            raise Exception("LLM client not configured")
        # Step 1: Use LLM to convert natural language to challenge JSON
        raw_json = reasoner._call_llm(prompt)
        # Clean up possible markdown blocks
        raw_json = raw_json.strip().replace("```json", "").replace("```", "").strip()
        challenge = json.loads(raw_json)
    except Exception as e:
        print(f"LLM mapping failed or not available, using heuristics...")
        challenge = _heuristic_challenge_from_instruction(user_input, available_tools)

    print(f"Mapped to category: {challenge.get('category')}")
    if challenge.get("files"):
        print(f"Target files: {challenge.get('files')}")
    if available_tools:
        print(f"Detected tools: {len(available_tools)} available")

    # Step 2: Initialize Tools and Coordinator
    from tools.web.browser_snapshot_tool import BrowserSnapshotTool
    from tools.crypto.john import JohnTool
    from tools.crypto.hashcat import HashcatTool
    
    browser_tool = BrowserSnapshotTool()
    john_tool = JohnTool()
    hashcat_tool = HashcatTool()
    
    coordinator = CoordinatorAgent(browser_snapshot_tool=browser_tool)
    coordinator.register_agent(CryptographyAgent(john_tool=john_tool, hashcat_tool=hashcat_tool))
    
    # Initialize WebExploitationAgent with its tools
    web_agent = WebExploitationAgent(browser_tool=browser_tool)
    coordinator.register_agent(web_agent)
    
    coordinator.register_agent(CodingAgent(reasoner=coordinator.reasoner))
    coordinator.register_agent(ForensicsAgent(john_tool=john_tool, hashcat_tool=hashcat_tool))
    coordinator.register_agent(ReverseEngineeringAgent(reasoner=coordinator.reasoner))
    coordinator.register_agent(OSINTAgent(browser_tool=browser_tool))
    coordinator.register_agent(LogAnalysisAgent())

    result = coordinator.solve_challenge(challenge)

    print("\n--- Final Result ---")
    print(f"Status: {result.get('status')}")
    print(f"Flag: {result.get('flag')}")
    print("\nSteps taken:")
    for step in result.get("steps", []):
        print(f"  - {step}")

if __name__ == "__main__":
    main()

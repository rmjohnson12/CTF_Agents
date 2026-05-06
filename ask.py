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
from agents.specialists.networking.networking_agent import NetworkingAgent
from core.decision_engine.llm_reasoner import LLMReasoner

def _normalize_path(p: str) -> str:
    """Robustly expand tilde and return absolute path, even if joined weirdly."""
    if "~" in p:
        # If ~ is buried (e.g. /cwd/~/path), extract from ~ onwards
        p = p[p.find("~"):]
    return os.path.abspath(os.path.expanduser(p))

def _extract_referenced_paths(user_input: str) -> List[str]:
    potential_paths = [
        w.strip(" \"',?!.;")
        for w in user_input.split()
    ]
    files_in_prompt = []
    for p in potential_paths:
        # Check if it looks like a path or if it's a file that exists in CWD
        if "/" in p or p.startswith("~") or os.path.isfile(p):
            full_path = _normalize_path(p)
            if os.path.exists(full_path) and os.path.isfile(full_path):
                files_in_prompt.append(full_path)

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
    url_match = re.search(r'(?:https?://|www\.)[^\s<>"]+|(?:\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b)', user_input)
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
        any(f.lower().endswith(('.pdf', '.pcap', '.pcapng')) for f in challenge_files)
        or (
            any(f.lower().endswith(('.bin', '.dat')) for f in challenge_files)
            and any(term in lowered_input for term in forensics_terms)
        )
        or any(term in lowered_input for term in ["forensics", "artifact"])
    ):
        category = "forensics"
    elif any(f.lower().endswith(('.py', '.exe', '.elf')) for f in challenge_files) or "authenticate" in lowered_input:
        category = "reverse"
    elif url or any(term in lowered_input for term in ["jwt", "session", "cookie", "token", ".cloud"]):
        category = "web"
    elif any(f.lower().endswith(('.txt', '.doc', '.docx')) for f in challenge_files) or any(term in lowered_input for term in crypto_terms):
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
    interactive = len(sys.argv) < 2
    user_input = " ".join(sys.argv[1:]) if not interactive else ""
    
    reasoner = LLMReasoner()
    from core.utils.system_checks import get_available_tools, get_system_context
    available_tools = get_available_tools()
    system_ctx = get_system_context()

    # Initialize Tools and Coordinator once
    from tools.web.browser_snapshot_tool import BrowserSnapshotTool
    from tools.crypto.john import JohnTool
    from tools.crypto.hashcat import HashcatTool
    
    browser_tool = BrowserSnapshotTool()
    john_tool = JohnTool()
    hashcat_tool = HashcatTool()
    
    coordinator = CoordinatorAgent(browser_snapshot_tool=browser_tool)
    coordinator.register_agent(CryptographyAgent(john_tool=john_tool, hashcat_tool=hashcat_tool))
    coordinator.register_agent(WebExploitationAgent(browser_tool=browser_tool))
    coordinator.register_agent(CodingAgent(reasoner=coordinator.reasoner))
    coordinator.register_agent(ForensicsAgent(john_tool=john_tool, hashcat_tool=hashcat_tool))
    coordinator.register_agent(ReverseEngineeringAgent(reasoner=coordinator.reasoner))
    coordinator.register_agent(OSINTAgent(browser_tool=browser_tool))
    coordinator.register_agent(LogAnalysisAgent())
    coordinator.register_agent(NetworkingAgent())

    challenge = None
    resume = False

    while True:
        if not user_input:
            if challenge and challenge.get("status") != "solved":
                print("\n--- The agent is stuck or needs more info ---")
                prompt_text = "Provide a hint, a new direction, or type 'exit' to quit: "
            else:
                prompt_text = "Enter your CTF instruction (or 'exit'): "
            
            try:
                user_input = input(f"\n{prompt_text}").strip()
            except EOFError:
                break
                
            if user_input.lower() in ["exit", "quit", "q"]:
                break
            if not user_input:
                continue

        print(f"\n--- Processing Instruction: \"{user_input}\" ---")

        if not challenge:
            # Step 1: Use LLM to convert natural language to challenge JSON
            prompt = f"""
Convert the following natural language security instruction into a standard CTF challenge JSON object.
Instruction: {user_input}

Current working directory: {os.getcwd()}
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
                raw_json = reasoner._call_llm(prompt)
                raw_json = raw_json.strip().replace("```json", "").replace("```", "").strip()
                challenge = json.loads(raw_json)
            except Exception as e:
                print(f"LLM mapping failed or not available, using heuristics...")
                challenge = _heuristic_challenge_from_instruction(user_input, available_tools)
        else:
            # Follow-up input: append to description and set resume
            challenge["description"] = (challenge.get("description") or "") + f"\n\nUser Hint: {user_input}"
            resume = True

        print(f"Target category: {challenge.get('category')}")
        if challenge.get("files"):
            # Normalize and expand paths
            challenge["files"] = [_normalize_path(f) for f in challenge["files"]]
            print(f"Target files: {challenge.get('files')}")

        # Step 2: Solve
        result = coordinator.solve_challenge(challenge, resume=resume)

        print("\n--- Step Result ---")
        print(f"Status: {result.get('status')}")
        print(f"Flag: {result.get('flag')}")
        
        if result.get("steps"):
            print("\nRecent steps:")
            for step in result.get("steps")[-5:]:
                print(f"  - {step}")

        if result.get("status") == "solved" or result.get("flag"):
            print("\nChallenge solved!")
            if interactive:
                challenge = None # Reset for next task
                user_input = ""
                resume = False
                continue
            else:
                break
        
        if not interactive:
            break
        
        user_input = "" # Clear for next loop iteration input

if __name__ == "__main__":
    main()

import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional

# Ensure we can import from project root
sys.path.insert(0, str(Path(__file__).resolve().parent))

from challenges.challenge_parser import ChallengeParser, ParseError
from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.specialists.cryptography.crypto_agent import CryptographyAgent
from agents.specialists.web_exploitation.web_agent import WebExploitationAgent
from agents.specialists.misc.coding_agent import CodingAgent
from agents.specialists.forensics.forensics_agent import ForensicsAgent
from agents.specialists.reverse_engineering.reverse_agent import ReverseEngineeringAgent
from agents.specialists.osint.osint_agent import OSINTAgent
from agents.specialists.log_analysis.log_agent import LogAnalysisAgent
from agents.specialists.networking.networking_agent import NetworkingAgent
from agents.support.docker_agent import DockerChallengeAgent
from agents.support.recon_agent import ReconAgent
from core.decision_engine.llm_reasoner import LLMReasoner

def _unwrap_ask_command(user_input: str) -> str:
    """Accept either a raw instruction or a pasted `python ask.py "..."` command."""
    try:
        parts = shlex.split(user_input)
    except ValueError:
        return user_input

    for idx, part in enumerate(parts):
        if os.path.basename(part) == "ask.py" and idx + 1 < len(parts):
            return " ".join(parts[idx + 1:])

    return user_input

def _normalize_path(p: str) -> str:
    """Robustly expand tilde and return absolute path, even if joined weirdly."""
    if "~" in p:
        # If ~ is buried (e.g. /cwd/~/path), extract from ~ onwards
        p = p[p.find("~"):]
    expanded = os.path.abspath(os.path.expanduser(p))
    if os.path.exists(expanded):
        return expanded

    # LLMs sometimes strip the leading "~/" and return Downloads/foo from a
    # prompt that said ~/Downloads/foo. Prefer the user's real Downloads path.
    if not os.path.isabs(p) and p.startswith("Downloads/"):
        home_download = os.path.join(os.path.expanduser("~"), p)
        if os.path.exists(home_download):
            return os.path.abspath(home_download)

    return expanded

def _normalize_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return url
    url = url.strip()
    if re.match(r"^https?://", url):
        return url
    if url.startswith("www.") or re.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/.*)?$", url):
        return "http://" + url
    return url

def _normalize_challenge(challenge: Dict[str, Any]) -> Dict[str, Any]:
    if challenge.get("url"):
        challenge["url"] = _normalize_url(challenge["url"])
    target = challenge.get("target")
    if isinstance(target, dict) and target.get("url"):
        target["url"] = _normalize_url(target["url"])
    return challenge

def _extract_referenced_paths(user_input: str) -> List[str]:
    potential_paths = [
        w.strip(" \"',?!.;")
        for w in user_input.split()
    ]
    files_in_prompt = []
    for p in potential_paths:
        # Check if it looks like a path or if it's a file/dir that exists in CWD
        if "/" in p or p.startswith("~") or os.path.exists(p):
            full_path = _normalize_path(p)
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
        return ChallengeParser().parse_file(path)
    except ParseError:
        return None
    except Exception:
        return None

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
        url = _normalize_url(url_match.group(0).strip(".,"))

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
    web_terms = ["jwt", "session", "cookie", "token", ".cloud", "http", "portal", "endpoint", "url", "site", "web", "docker", "dockerfile", "container"]

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
    elif url or any(term in lowered_input for term in web_terms):
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

def _print_plan(
    challenge: Dict[str, Any],
    analysis: Dict[str, Any],
    next_action: Dict[str, Any],
    tracker=None,
) -> None:
    """Print a routing plan without invoking any agents or tools."""
    conf_pct = f"{analysis['confidence'] * 100:.0f}%"
    indicators = ", ".join(analysis["strategy"]["detected_indicators"]) or "none"
    action = next_action.get("next_action", "stop")
    target = next_action.get("target", "none")
    routing = f"{action} -> {target}" if target != "none" else "stop  (no confident path)"

    print("\n=== Plan (dry run) ===\n")
    print(f"Challenge : {challenge.get('name', 'Unknown')}  [{challenge.get('id', '?')}]")
    print(f"Category  : {analysis['category']}  ({conf_pct} confidence)")
    print(f"Indicators: {indicators}")
    print()
    print(f"Routing   : {routing}")
    print(f"Reasoning : {next_action.get('reasoning') or analysis['strategy']['reasoning']}")

    if tracker is not None:
        hint = tracker.get_routing_hint(analysis["category"])
        if hint:
            agent_id, rate = hint
            print()
            print(
                f"Perf hint : {agent_id} -> {rate:.0%} historical solve rate "
                f"for '{analysis['category']}' challenges"
            )
        else:
            print()
            print(f"Perf hint : No history yet for '{analysis['category']}' challenges")

    print()
    print("No agents or tools were invoked. Remove --plan to execute.")


def main():
    plan_mode = "--plan" in sys.argv
    if plan_mode:
        sys.argv = [a for a in sys.argv if a != "--plan"]

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
    coordinator.register_agent(DockerChallengeAgent())
    coordinator.register_agent(ReconAgent())

    if plan_mode:
        if not user_input:
            print("Usage: python ask.py --plan \"your instruction\"")
            print("       python ask.py --plan path/to/challenge.json")
            return
        heuristic = _heuristic_challenge_from_instruction(user_input, available_tools)
        challenge = _normalize_challenge(ChallengeParser().parse_dict(heuristic))
        if challenge.get("files"):
            challenge["files"] = [_normalize_path(f) for f in challenge["files"]]
        raw_analysis = coordinator.reasoner.analyze_challenge(challenge)
        analysis_dict = coordinator._analysis_to_dict(challenge, raw_analysis)
        next_action = coordinator.reasoner.choose_next_action(challenge, raw_analysis, [])
        _print_plan(challenge, analysis_dict, next_action, coordinator.performance_tracker)
        return

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
            user_input = _unwrap_ask_command(user_input)

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
Do NOT invent, guess, or hallucinate a url (like localhost:8080) if one is not clearly specified in the instruction. If there is no url, omit the field.
"""
            try:
                if reasoner.client is None:
                    raise Exception("LLM client not configured")
                raw_json = reasoner._call_llm(prompt)
                raw_json = raw_json.strip().replace("```json", "").replace("```", "").strip()
                llm_dict = json.loads(raw_json)
                challenge = _normalize_challenge(ChallengeParser().parse_dict(llm_dict))
            except ParseError:
                print(f"LLM produced an invalid challenge shape, using heuristics...")
                challenge = _normalize_challenge(ChallengeParser().parse_dict(
                    _heuristic_challenge_from_instruction(user_input, available_tools)
                ))
            except Exception:
                print(f"LLM mapping failed or not available, using heuristics...")
                challenge = _normalize_challenge(ChallengeParser().parse_dict(
                    _heuristic_challenge_from_instruction(user_input, available_tools)
                ))
        else:
            # Follow-up input: append to description and set resume
            challenge["description"] = (challenge.get("description") or "") + f"\n\nUser Hint: {user_input}"
            resume = True
            challenge = _normalize_challenge(challenge)

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

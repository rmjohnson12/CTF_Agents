import argparse
import hashlib
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
from agents.registry import AgentRegistry
from tools.common.elf_utils import is_elf_binary

def _parse_cli_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ask.py",
        description="Run the natural-language CTF agent CLI.",
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="Print the routing plan without invoking agents or tools.",
    )
    parser.add_argument(
        "instruction",
        nargs=argparse.REMAINDER,
        help="Challenge instruction text, pasted ask.py command, or challenge path.",
    )
    return parser.parse_args(argv)

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

    corrected = _correct_common_home_path_typo(p)
    if corrected:
        return corrected

    # LLMs sometimes strip the leading "~/" and return Downloads/foo from a
    # prompt that said ~/Downloads/foo. Prefer the user's real Downloads path.
    if not os.path.isabs(p) and p.startswith("Downloads/"):
        home_download = os.path.join(os.path.expanduser("~"), p)
        if os.path.exists(home_download):
            return os.path.abspath(home_download)

    return expanded


def _correct_common_home_path_typo(path_text: str) -> Optional[str]:
    """Recover common home-folder typos only when the corrected path exists."""
    raw = str(path_text).strip()
    replacements = {
        "~/Downlaods/": "~/Downloads/",
        "~/Downlaods": "~/Downloads",
        "~/Donwloads/": "~/Downloads/",
        "~/Donwloads": "~/Downloads",
    }
    for wrong, right in replacements.items():
        if raw == wrong or raw.startswith(wrong):
            candidate = os.path.abspath(os.path.expanduser(right + raw[len(wrong):]))
            if os.path.exists(candidate):
                return candidate
    return None

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
    if challenge.get("files"):
        challenge["files"] = _expand_challenge_artifacts([
            _normalize_path(str(path)) for path in challenge["files"]
        ])
    return challenge

def _merge_heuristic_context(
    challenge: Dict[str, Any],
    heuristic: Dict[str, Any],
) -> Dict[str, Any]:
    """Preserve concrete user-supplied context when LLM mapping omits it."""
    if not challenge.get("url") and heuristic.get("url"):
        challenge["url"] = heuristic["url"]
    if heuristic.get("id"):
        challenge["id"] = heuristic["id"]

    # Heuristic files are grounded in paths found in the user's instruction.
    # LLM files may be stale or hallucinated, and if they happen to exist
    # locally they can contaminate a fresh prompt with artifacts from a prior
    # challenge. Treat the heuristic as the source of truth for local files.
    challenge["files"] = sorted(set(heuristic.get("files") or []))

    # When the heuristic derived a specific category from real files on disk,
    # trust it over the LLM — the LLM can misclassify based on keywords alone.
    _HEURISTIC_WINS = {"reverse", "pwn", "hardware", "forensics", "blockchain"}
    heuristic_cat = heuristic.get("category", "")
    heuristic_description = heuristic.get("description") or ""
    if heuristic_cat in _HEURISTIC_WINS and heuristic.get("files"):
        challenge["category"] = heuristic_cat
    elif heuristic_cat in _HEURISTIC_WINS and _instruction_declares_category(
        heuristic_description,
        heuristic_cat,
    ):
        challenge["category"] = heuristic_cat
    elif (
        heuristic.get("url")
        and heuristic_cat == "web"
        and (not heuristic.get("files"))
    ):
        challenge["category"] = "web"

    description = challenge.get("description") or ""
    if heuristic.get("url") and heuristic.get("url") not in description:
        challenge["description"] = f"{description}\n\nOriginal instruction: {heuristic_description}".strip()

    return challenge


def _looks_like_new_challenge_instruction(user_input: str) -> bool:
    """Detect a fresh challenge prompt in interactive mode."""
    lowered = user_input.lower()
    has_target = bool(re.search(
        r"(?:https?://|www\.)[^\s<>\"]+|(?:\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b)",
        user_input,
    ))
    has_file_locator = any(
        phrase in lowered
        for phrase in ("files are in", "file is in", "files are located", "the files are")
    )
    has_challenge_word = "challenge" in lowered
    return has_target or has_file_locator or has_challenge_word


def _heuristic_mapping_is_actionable(heuristic: Dict[str, Any]) -> bool:
    """Return True when local parsing is concrete enough to skip LLM mapping."""
    category = str(heuristic.get("category") or "").lower()
    if category in {"", "unknown", "misc"}:
        return False
    if _instruction_declares_category(str(heuristic.get("description") or ""), category):
        return True
    return bool(heuristic.get("files") or heuristic.get("url") or heuristic.get("target"))


def _instruction_declares_category(text: str, category: str) -> bool:
    return _declared_category_from_instruction(text) == category


def _declared_category_from_instruction(text: str) -> Optional[str]:
    lowered = text.lower()
    declared_patterns = {
        "reverse": [
            r"\breversing\s+challenge\b",
            r"\breverse[-\s]+engineering\s+challenge\b",
            r"\brev\s+challenge\b",
            r"\bcrackme\b",
            r"\bdecompile\b",
            r"\bdisassemble\b",
            r"\breverse\s+engineer\b",
        ],
        "pwn": [r"\bpwn\s+challenge\b", r"\bbinary\s+exploitation\s+challenge\b"],
        "hardware": [r"\bhardware\s+challenge\b", r"\bchip\s+challenge\b"],
        "blockchain": [r"\bblockchain\s+challenge\b", r"\bsmart\s+contract\s+challenge\b"],
        "secure_coding": [r"\bsecure[-\s]+coding\s+challenge\b"],
        "web": [r"\bweb\s+challenge\b"],
        "forensics": [r"\bforensics\s+challenge\b"],
        "crypto": [r"\bcrypto\s+challenge\b", r"\bcryptography\s+challenge\b"],
        "log": [r"\blog\s+challenge\b"],
    }
    for category in (
        "secure_coding",
        "blockchain",
        "hardware",
        "reverse",
        "pwn",
        "crypto",
        "forensics",
        "web",
        "log",
    ):
        if any(re.search(pattern, lowered) for pattern in declared_patterns.get(category, [])):
            return category
    return None


def _should_disable_llm_for_direct_cli(
    user_input: str,
    available_tools: List[str],
    plan_mode: bool,
) -> bool:
    """Keep deterministic direct pwn one-shot runs out of provider calls."""
    if plan_mode or not user_input:
        return False
    if os.getenv("CTF_AGENTS_ENABLE_LLM_FOR_DIRECT_PWN") == "1":
        return False

    heuristic = _heuristic_challenge_from_instruction(user_input, available_tools)
    category = str(heuristic.get("category") or "").lower()
    return category in {"pwn", "binary"} and _heuristic_mapping_is_actionable(heuristic)


def _challenge_id_from_instruction(
    user_input: str,
    url: Optional[str],
    category: Optional[str] = None,
) -> str:
    """Build a stable per-prompt id so unrelated ad hoc runs do not share state."""
    basis = url or user_input
    digest = hashlib.sha256(basis.encode("utf-8", errors="ignore")).hexdigest()[:8]
    prefix = re.sub(r"[^A-Za-z0-9]+", "_", str(category or "heuristic")).strip("_").lower()
    prefix = prefix or "heuristic"
    if url:
        host = re.sub(r"^https?://", "", url).split("/", 1)[0].split(":", 1)[0]
        slug = re.sub(r"[^A-Za-z0-9]+", "_", host).strip("_").lower()
        return f"{prefix}_{slug}_{digest}" if slug else f"{prefix}_{digest}"
    return f"heuristic_{digest}"


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


def _expand_challenge_artifacts(paths: List[str]) -> List[str]:
    """
    Expand small challenge directories into files the agents can inspect.

    Wordlist/tool directories are intentionally kept out of challenge files so
    crypto agents do not waste time treating giant dictionaries as artifacts.
    """
    expanded: List[str] = []
    skip_dir_terms = {"wordlist", "wordlists", "rockyou", "payload", "payloads"}
    useful_exts = {
        ".enc", ".bin", ".dat", ".txt", ".json", ".py", ".c", ".cpp", ".java",
        ".go", ".sh", ".pcap", ".pcapng", ".pdf", ".zip", ".log",
        ".csv", ".jpg", ".jpeg", ".png", ".v", ".sv", ".vhdl", ".vhd",
        ".exe", ".pck", ".gd", ".gdc", ".sol",
    }

    for path in paths:
        p = Path(path)
        lower_parts = {part.lower() for part in p.parts}
        if p.is_dir():
            if lower_parts & skip_dir_terms:
                continue
            if _is_broad_artifact_directory(p):
                continue
            if (p / "Dockerfile").exists():
                expanded.append(str(p.resolve()))
                continue
            for child in sorted(p.rglob("*")):
                if not child.is_file():
                    continue
                if child.suffix.lower() in useful_exts:
                    expanded.append(str(child.resolve()))
                elif re.fullmatch(r"(?:libc|ld)[^/]*\.so(?:\.\d+)*", child.name.lower()):
                    # Bundled dynamic loaders and libc builds are first-class
                    # pwn artifacts even though pathlib sees `.6` as the
                    # suffix of names such as libc.so.6.
                    expanded.append(str(child.resolve()))
                elif not child.suffix and is_elf_binary(str(child)):
                    expanded.append(str(child.resolve()))
        else:
            expanded.append(str(p.resolve()))

    return sorted(set(expanded))


def _is_broad_artifact_directory(path: Path) -> bool:
    """Avoid expanding catch-all user folders such as ~/Downloads."""
    try:
        resolved = path.expanduser().resolve()
        home = Path.home().resolve()
    except OSError:
        return False

    broad_dirs = {
        home,
        home / "Downloads",
        home / "Desktop",
        home / "Documents",
    }
    return resolved in broad_dirs

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
        metadata["loaded_from_challenge_json"] = True
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
        "crypto",
        "cryptography",
        "rsa",
        "public key",
        "time capsule",
    ]
    strong_crypto_terms = [
        term
        for term in crypto_terms
        if term not in {"password", "rockyou"}
    ]

    referenced_artifacts = [
        path for path in files_in_prompt
        if _load_challenge_json(path) is None
    ]
    challenge_files = _expand_challenge_artifacts(referenced_artifacts)

    forensics_terms = ["hidden", "artifact", "forensics", "extract", "embedded", "strings"]

    coding_terms = ["calculate", "sum", "prime", "algorithm", "program", "script", "format ctf"]
    web_terms = ["jwt", "session", "cookie", "token", ".cloud", "http", "portal", "endpoint", "url", "site", "web", "docker", "dockerfile", "container"]
    pwn_terms = ["pwn", "overflow", "rop", "ret2libc", "shellcode", "buffer overflow"]
    hardware_terms = ["hardware", "chip", "logic", "circuit", "gate", "verilog", "vhdl", "schematic"]
    secure_coding_terms = [
        "secure coding",
        "secure-coding",
        "fix the vulnerability",
        "patch the vulnerability",
        "source patch",
        "patch source",
        "vulnerable code",
        "remediate",
    ]
    blockchain_terms = [
        "blockchain",
        "solidity",
        "smart contract",
        "web3",
    ]
    has_hardware_term = any(
        re.search(r"\b" + re.escape(term) + r"\b", lowered_input)
        for term in hardware_terms
    )
    has_log_term = any(
        re.search(pattern, lowered_input)
        for pattern in (
            r"\blog(?:s|file| analysis)?\b",
            r"\bauth(?:entication)?(?:\s+log|\s+events?)?\b",
            r"\bssh\b",
            r"\bbrute force\b",
            r"\bfailed password\b",
        )
    )
    declared_category = _declared_category_from_instruction(user_input)

    if declared_category:
        category = declared_category
    elif any(term in lowered_input for term in secure_coding_terms):
        category = "secure_coding"
    elif (
        any(f.lower().endswith(".sol") for f in challenge_files)
        or any(term in lowered_input for term in blockchain_terms)
    ):
        category = "blockchain"
    elif (
        has_hardware_term
        or (
            any(f.lower().endswith((".csv", ".v", ".sv", ".vhdl", ".vhd")) for f in challenge_files)
            and any(f.lower().endswith((".jpg", ".jpeg", ".png")) for f in challenge_files)
        )
    ):
        category = "hardware"
    elif any(f.lower().endswith((".exe", ".pck", ".gdc")) for f in challenge_files):
        # PE/Windows binaries are always reversing — never pwn or log
        category = "reverse"
    elif re.search(r"\barms?\s+race\b", lowered_input):
        # CTF wording commonly hides an ARM architecture hint in "ARMs race".
        # Keep this ahead of the generic host/URL rule so a raw TCP reversing
        # service is not mistaken for a web application.
        category = "reverse"
    elif has_log_term:
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
    elif (
        # Binary + encrypted output = encryptor reversing, not pure crypto
        any(not Path(f).suffix and is_elf_binary(f) for f in challenge_files)
        and any(f.lower().endswith(('.enc', '.encrypted', '.bin', '.dat')) for f in challenge_files)
    ) or (
        # Ambiguous wording — bare "reverse" also shows up in "reverse shell",
        # "reverse proxy", etc. Only treat as reversing when an actual ELF
        # binary is attached.
        any(term in lowered_input for term in [
            "ransomware", "encryption program", "reverse",
            "godot", "game loader", "compromised",
        ])
        and any(not Path(f).suffix and is_elf_binary(f) for f in challenge_files)
    ) or any(
        # Unambiguous reverse-engineering wording: trust it even if the
        # referenced binary is missing (e.g. a mistyped path). Never fall
        # through to "misc" when the user explicitly said it's a reversing
        # challenge.
        re.search(r"\b" + re.escape(term) + r"\b", lowered_input)
        for term in [
            "reversing", "reverse engineer", "reverse-engineer",
            "reverse engineering", "decompile", "disassemble", "crackme",
        ]
    ):
        category = "reverse"
    elif challenge_files and any(term in lowered_input for term in strong_crypto_terms):
        category = "crypto"
    elif (
        any(term in lowered_input for term in pwn_terms)
        or (
            any(f.lower().endswith('.elf') or (not Path(f).suffix and is_elf_binary(f)) for f in challenge_files)
            and any(term in lowered_input for term in ["exploit", "pwn", "overflow", "binary", "attack"])
        )
    ):
        category = "pwn"
    elif url or any(term in lowered_input for term in web_terms):
        category = "web"
    elif (
        any(f.lower().endswith(('.txt', '.doc', '.docx', '.enc')) for f in challenge_files)
        or any(term in lowered_input for term in strong_crypto_terms)
    ):
        category = "crypto"
    elif (
        any(f.lower().endswith(('.py', '.exe', '.elf')) for f in challenge_files)
        or any(not Path(f).suffix and is_elf_binary(f) for f in challenge_files)
        or "authenticate" in lowered_input
    ):
        category = "reverse"
    elif any(term in lowered_input for term in coding_terms):
        category = "misc"

    return {
        "id": _challenge_id_from_instruction(user_input, url, category),
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


def main(argv: Optional[List[str]] = None):
    args = _parse_cli_args(sys.argv[1:] if argv is None else argv)
    plan_mode = args.plan
    user_input = " ".join(args.instruction).strip()
    interactive = not user_input and not plan_mode
    
    from core.utils.system_checks import get_available_tools, get_system_context
    available_tools = get_available_tools()
    if _should_disable_llm_for_direct_cli(user_input, available_tools, plan_mode):
        os.environ["LLM_PROVIDER"] = "none"
    system_ctx = get_system_context()

    # Initialize Tools and Coordinator once
    from tools.web.browser_snapshot_tool import BrowserSnapshotTool
    from tools.crypto.john import JohnTool
    from tools.crypto.hashcat import HashcatTool
    
    browser_tool = BrowserSnapshotTool()
    john_tool = JohnTool()
    hashcat_tool = HashcatTool()
    
    coordinator = CoordinatorAgent(browser_snapshot_tool=browser_tool)
    AgentRegistry.register_all(coordinator, {
        "browser_tool": browser_tool,
        "john_tool": john_tool,
        "hashcat_tool": hashcat_tool,
        "reasoner": coordinator.reasoner,
    })

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

        if challenge and _looks_like_new_challenge_instruction(user_input):
            challenge = None
            resume = False

        if not challenge:
            heuristic = _heuristic_challenge_from_instruction(user_input, available_tools)
            if (heuristic.get("metadata") or {}).get("loaded_from_challenge_json"):
                challenge = _normalize_challenge(ChallengeParser().parse_dict(heuristic))
            elif _heuristic_mapping_is_actionable(heuristic):
                challenge = _normalize_challenge(ChallengeParser().parse_dict(heuristic))
            else:
                # Step 1: Use LLM to convert natural language to challenge JSON
                actual_files = heuristic.get("files") or []
                files_hint = (
                    f"\nActual files found on disk (use EXACTLY these paths, do not invent others): {actual_files}"
                    if actual_files else ""
                )
                prompt = f"""
Convert the following natural language security instruction into a standard CTF challenge JSON object.
Instruction: {user_input}

Current working directory: {os.getcwd()}
{system_ctx}{files_hint}

Return ONLY the JSON object.
Example shape:
{{
  "id": "transient_task",
  "name": "Manual Task",
  "category": "forensics|web|crypto|hardware|blockchain|secure_coding|misc",
  "description": "...",
  "files": ["path/to/file"],
  "url": "..."
}}
Do NOT invent, guess, or hallucinate file paths or a url (like localhost:8080) if one is not clearly specified in the instruction. If there is no url, omit the field.
"""
                try:
                    if coordinator.reasoner.client is None:
                        raise Exception("LLM client not configured")
                    raw_json = coordinator.reasoner._call_llm(prompt)
                    raw_json = raw_json.strip().replace("```json", "").replace("```", "").strip()
                    llm_dict = json.loads(raw_json)
                    challenge = _normalize_challenge(
                        _merge_heuristic_context(ChallengeParser().parse_dict(llm_dict), heuristic)
                    )
                except ParseError:
                    print(f"LLM produced an invalid challenge shape, using heuristics...")
                    challenge = _normalize_challenge(ChallengeParser().parse_dict(heuristic))
                except Exception:
                    print(f"LLM mapping failed or not available, using heuristics...")
                    challenge = _normalize_challenge(ChallengeParser().parse_dict(heuristic))
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

        routing_summary = result.get("routing_summary") or {}
        if routing_summary:
            evidence = ", ".join(routing_summary.get("evidence") or []) or "none"
            fallbacks = " -> ".join(routing_summary.get("fallback_chain") or []) or "none"
            print("\n--- Routing Summary ---")
            print(
                f"Category: {routing_summary.get('category')} "
                f"({float(routing_summary.get('confidence') or 0) * 100:.0f}% confidence)"
            )
            print(f"Evidence: {evidence}")
            print(
                f"Selected: {routing_summary.get('selected_action')} -> "
                f"{routing_summary.get('selected_target')}"
            )
            print(f"Fallbacks: {fallbacks}")

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
    _one_shot_cli = len(sys.argv) > 1
    _exit_code = 0
    try:
        main()
    except KeyboardInterrupt:
        _exit_code = 130
        print("\nInterrupted.", file=sys.stderr)
    except Exception:
        _exit_code = 1
        import traceback
        traceback.print_exc()
    finally:
        if _one_shot_cli:
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(_exit_code)
    sys.exit(_exit_code)

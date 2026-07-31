import importlib
import os
import platform
import shutil
import sys
from pathlib import Path
from dotenv import load_dotenv

from tools.common.cross_arch_runner import CrossArchElfRunner, docker_bin

def _load_nvidia_keys():
    raw_keys = []
    for env_name in ("NVAPI_KEYS", "NVAPI_KEY", "NGC_API_KEY"):
        raw_keys.extend((os.getenv(env_name) or "").split(","))

    keys = []
    for key in raw_keys:
        key = key.strip()
        if key and key not in keys:
            keys.append(key)
    return keys

def _playwright_failure_message(exc):
    message = str(exc)
    lowered = message.lower()
    missing_browser_markers = (
        "executable doesn't exist",
        "please run the following command to download new browsers",
        "playwright install",
    )
    if any(marker in lowered for marker in missing_browser_markers):
        return (
            f"[!] Playwright Chromium: NOT FOUND ({message})",
            "    Run: python3 -m playwright install chromium",
        )

    return (
        f"[!] Playwright Chromium: LAUNCH FAILED ({message})",
        "    Browser is installed, but could not start. Check sandbox, temp directory, or OS permissions.",
    )

def _live_llm_ping(reasoner):
    """Actually call the LLM once so a configured-but-broken provider (dead
    model, exhausted quota, revoked key) is caught here instead of silently
    degrading every solve to heuristic-only mode."""
    if "--no-ping" in sys.argv:
        print("[i] Live LLM ping: SKIPPED (--no-ping)")
        return
    reply = reasoner._call_llm("Reply with exactly the word PONG and nothing else.")
    summary = reasoner.runtime_summary()
    if reply and "pong" in reply.lower():
        print(
            f"[+] Live LLM ping: OK via {summary['active_provider']} "
            f"({summary['active_model']})"
        )
    else:
        reason = summary.get("disabled_reason") or "no provider returned a response"
        print(f"[!] Live LLM ping: FAILED ({reason})")
        print("    Every solve will run in HEURISTIC-ONLY mode until this is fixed.")


def check():
    print("=== CTF_Agents: Pre-Flight Check ===")
    load_dotenv()
    
    # 1. Check API Keys & Mode
    provider = (os.getenv("LLM_PROVIDER") or "").strip().lower()
    openai_key = os.getenv("OPENAI_API_KEY")
    nvidia_keys = _load_nvidia_keys()
    nvapi_key = nvidia_keys[0] if nvidia_keys else None
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    google_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
    google_cloud_requested = provider in {"google", "gemini", "vertex", "vertexai"} or (
        (os.getenv("GOOGLE_GENAI_USE_VERTEXAI") or "").strip().lower() in {"1", "true", "yes"}
        or (os.getenv("GOOGLE_GENAI_USE_ENTERPRISE") or "").strip().lower() in {"1", "true", "yes"}
    )
    google_project = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GOOGLE_PROJECT_ID")
    google_location = os.getenv("GOOGLE_CLOUD_LOCATION") or os.getenv("GOOGLE_LOCATION") or "global"
    ollama_requested = provider in {"ollama", "local"}
    ollama_base_url = os.getenv("OLLAMA_BASE_URL") or "http://localhost:11434/v1"
    ollama_model = os.getenv("OLLAMA_MODEL") or "llama3.1"
    
    has_llm = False
    if nvapi_key:
        suffix = f" ({len(nvidia_keys)} keys)" if len(nvidia_keys) > 1 else ""
        print(f"[+] NVIDIA NIM API Key: CONFIGURED{suffix}")
        has_llm = True
    else:
        print("[-] NVIDIA NIM API Key: MISSING")

    if anthropic_key and anthropic_key != "your_anthropic_api_key_here":
        print("[+] Anthropic API Key: CONFIGURED")
        has_llm = True
    else:
        print("[-] Anthropic API Key: MISSING")
        
    if openai_key and openai_key != "your_openai_api_key_here":
        print("[+] OpenAI API Key: CONFIGURED")
        has_llm = True
    else:
        print("[-] OpenAI API Key: MISSING")

    if google_key and not google_key.startswith("your_"):
        print("[+] Google Gemini API Key: CONFIGURED")
        has_llm = True
    elif google_cloud_requested and google_project:
        print(f"[+] Google Gemini Cloud ADC: CONFIGURED ({google_project}, {google_location})")
        has_llm = True
    else:
        print("[-] Google Gemini API Key/ADC: MISSING")

    if ollama_requested:
        print(f"[+] Ollama local model: CONFIGURED ({ollama_model} at {ollama_base_url})")
        has_llm = True

    if has_llm:
        print("[+] Mode: LLM-assisted (LLM-backed routing and planning enabled)")
        if provider:
            print(f"[+] Preferred LLM provider: {provider}")
            if provider in {"ollama", "local"}:
                print("[+] Selected LLM provider: ollama")
            elif provider in {"google", "gemini", "vertex", "vertexai"} and (google_key or google_project):
                print("[+] Selected LLM provider: google")
            elif provider in {"anthropic", "claude"} and not anthropic_key and nvapi_key:
                print("[+] Selected LLM provider: nvidia (Anthropic key missing; falling back)")
            elif provider in {"nvidia", "nim"} and not nvapi_key and anthropic_key:
                print("[+] Selected LLM provider: anthropic (NVIDIA key missing; falling back)")
        elif nvapi_key:
            print("[+] Selected LLM provider: nvidia")
        elif anthropic_key:
            print("[+] Selected LLM provider: anthropic")
        elif openai_key:
            print("[+] Selected LLM provider: openai")
        elif google_key or google_project:
            print("[+] Selected LLM provider: google")
        try:
            from core.decision_engine.llm_reasoner import LLMReasoner
            reasoner = LLMReasoner()
            runtime_chain = reasoner.runtime_summary()["configured_providers"]
            if runtime_chain:
                print(f"[+] Runtime LLM failover chain: {' -> '.join(runtime_chain)}")
            _live_llm_ping(reasoner)
        except Exception as exc:
            print(f"[!] Could not initialize the LLM failover chain: {exc}")
    else:
        print("[!] Mode: HEURISTIC (Running without LLM; using pattern matching for routing)")

    # 2. Check Playwright
    print("\n--- Browser Environment ---")
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(headless=True)
                browser.close()
                print("[+] Playwright Chromium: INSTALLED")
            except Exception as e:
                status_line, remediation = _playwright_failure_message(e)
                print(status_line)
                print(remediation)
    except ImportError:
        print("[-] Playwright Library: NOT INSTALLED (Run: pip install playwright)")

    # 3. Check Security Tools
    print("\n--- Security Tooling ---")
    tools = {
        "REQUIRED": ["python3", "curl"],
        "OPTIONAL (Web)": ["sqlmap", "dirsearch"],
        "OPTIONAL (Crypto)": ["hashcat", "john"],
        "OPTIONAL (Forensics)": ["binwalk", "exiftool", "tshark", "qpdf"]
    }
    
    for category, tool_list in tools.items():
        found = []
        missing = []
        for t in tool_list:
            if shutil.which(t):
                found.append(t)
            else:
                missing.append(t)
        
        status = "[+]" if not missing or "OPTIONAL" in category else "[!]"
        if "REQUIRED" in category and missing:
            status = "[!]"
            
        print(f"{status} {category}: {', '.join(found)} " + (f"(MISSING: {', '.join(missing)})" if missing else ""))

    # 4. Check solver backends
    #
    # These are imported lazily by the specialists, so a broken one does not
    # crash anything - it just silently removes whole attack classes from the
    # agents' reach. Surface them here instead.
    print("\n--- Solver Backends ---")
    backends = {
        "fpylll": "lattice reduction (RSA Coppersmith / partial-key recovery)",
        "sympy": "polynomial roots, discrete logs",
        "z3": "constraint solving (custom cipher inversion)",
        "Crypto": "pycryptodome primitives",
        "gmpy2": "big-integer speedups",
        "solcx": "Solidity compilation (source-driven attacker contracts)",
    }
    for module, purpose in backends.items():
        try:
            importlib.import_module(module)
            print(f"[+] {module}: INSTALLED ({purpose})")
        except Exception as exc:
            print(f"[-] {module}: UNAVAILABLE ({purpose}) — {type(exc).__name__}: {exc}")

    # 5. Check the reversing / pwn stack
    #
    # Same fail-open problem as the solver backends: the pwn agent skips Ghidra
    # when GHIDRA_HOME is unset and skips angr when it is not importable, and a
    # run only says "skipped" in a trace nobody reads. Local execution is worse
    # - a Linux ELF simply cannot run on a non-Linux or foreign-arch host, and
    # the failure looks like a broken exploit.
    print("\n--- Reversing / Pwn Stack ---")
    for module, purpose in {
        "angr": "symbolic execution (automatic win-input discovery)",
        "pwn": "pwntools: payload delivery, cyclic offsets, ROP",
        "capstone": "disassembly",
        "unicorn": "CPU emulation",
    }.items():
        try:
            importlib.import_module(module)
            print(f"[+] {module}: INSTALLED ({purpose})")
        except Exception as exc:
            print(f"[-] {module}: UNAVAILABLE ({purpose}) — {type(exc).__name__}: {exc}")

    ghidra_home = os.getenv("GHIDRA_HOME")
    if ghidra_home and Path(ghidra_home).is_dir():
        print(f"[+] GHIDRA_HOME: {ghidra_home}")
    elif ghidra_home:
        print(f"[-] GHIDRA_HOME: set to {ghidra_home} but that is not a directory")
    else:
        print("[-] GHIDRA_HOME: unset (static analysis phase will be skipped)")

    print("[+] checksec: INSTALLED" if shutil.which("checksec")
          else "[-] checksec: MISSING (mitigation detection falls back to heuristics)")

    # Local execution of challenge binaries.
    host_os, host_arch = platform.system(), platform.machine()
    if host_os == "Linux":
        print(f"[+] Native ELF execution: available ({host_os}/{host_arch})")
    else:
        print(f"[!] Native ELF execution: UNAVAILABLE — host is {host_os}/{host_arch}, "
              "challenge binaries are Linux ELFs")

    runner = CrossArchElfRunner()
    if not runner.cli_available():
        print(f"[-] Emulated ELF execution: no '{docker_bin()}' CLI on PATH "
              "(set CTF_AGENTS_DOCKER_BIN for another runtime)")
    else:
        ok, detail = runner.daemon_available()
        if ok:
            print(f"[+] Emulated ELF execution: available via {detail}")
        else:
            print(f"[-] Emulated ELF execution: {detail}")

    # 6. Check Workspace
    print("\n--- Workspace ---")
    rockyou = Path.home() / "Downloads" / "rockyou.txt"
    if rockyou.exists():
        print(f"[+] Wordlist: Found at {rockyou}")
    else:
        # Check current dir too
        local_rockyou = Path("rockyou.txt")
        if local_rockyou.exists():
            print(f"[+] Wordlist: Found at {local_rockyou.absolute()}")
        else:
            print(f"[-] Wordlist: rockyou.txt not found (Cracking will be limited)")

    print("\n[!] Setup check complete.")

if __name__ == "__main__":
    check()

import os
import shutil
import sys
from pathlib import Path
from dotenv import load_dotenv

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

    # 4. Check Workspace
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

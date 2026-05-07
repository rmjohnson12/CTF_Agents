import os
import shutil
import sys
from pathlib import Path
from dotenv import load_dotenv

def check():
    print("=== CTF_Agents: Pre-Flight Check ===")
    load_dotenv()
    
    # 1. Check API Keys & Mode
    provider = (os.getenv("LLM_PROVIDER") or "").strip().lower()
    openai_key = os.getenv("OPENAI_API_KEY")
    nvapi_key = os.getenv("NVAPI_KEY") or os.getenv("NGC_API_KEY")
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    
    has_llm = False
    if nvapi_key:
        print("[+] NVIDIA NIM API Key: CONFIGURED")
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

    if has_llm:
        print("[+] Mode: LLM-assisted (LLM-backed routing and planning enabled)")
        if provider:
            print(f"[+] Preferred LLM provider: {provider}")
            if provider in {"anthropic", "claude"} and not anthropic_key and nvapi_key:
                print("[+] Selected LLM provider: nvidia (Anthropic key missing; falling back)")
            elif provider in {"nvidia", "nim"} and not nvapi_key and anthropic_key:
                print("[+] Selected LLM provider: anthropic (NVIDIA key missing; falling back)")
        elif nvapi_key:
            print("[+] Selected LLM provider: nvidia")
        elif anthropic_key:
            print("[+] Selected LLM provider: anthropic")
        elif openai_key:
            print("[+] Selected LLM provider: openai")
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
                print(f"[!] Playwright Chromium: NOT FOUND ({e})")
                print("    Run: python3 -m playwright install chromium")
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

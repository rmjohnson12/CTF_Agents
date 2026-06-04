# CTF_Agents

CTF_Agents is a Python multi-agent system for authorized Capture The Flag
workflows. It routes challenge prompts to specialist agents, runs security tools
through a common wrapper layer, captures observations, and iterates until it can
report a result or explain what blocked progress.

The fastest way to use it is the natural-language CLI in `ask.py`. You describe
the task, the router maps it to the best specialist, and the coordinator manages
the solving loop.

## What It Can Work On

- Reverse engineering tasks involving Python files, ELF binaries, Windows
  PE/EXE files, and Godot game packages. The reverse agent automatically unpacks UPX-compressed
  binaries (ELF and PE), reverses glibc `rand()`-based XOR+ROL encryption
  (recovering the seed from the encrypted file), extracts crackme passwords
  from `.rodata`/`.rdata` fragments, decodes numeric-encoded flags (char_code
  × N stored as integer sequences), handles anti-decompilation patterns such
  as `ud2`/SIGILL signal-handler tricks, decrypts obfuscated .NET assemblies
  by extracting and AES-decrypting the embedded managed resource then parsing
  the `BinaryReader` string table, and reverses AES-NI self-decrypting
  shellcode PE challenges (AESKEYGENASSIST + AESDECLAST 1-round cipher with
  block-index key, extracting per-character flag comparisons from decrypted
  shellcode stubs via capstone disassembly). Godot loader playbooks can recover
  embedded PCK AES keys, decompile scripts with GDRE Tools when available,
  emulate obfuscated GDScript array/string construction, replay expected C2
  headers, and combine split flags from local scripts plus remote responses.
- Cryptography and password-cracking tasks using hashes, encodings, wordlists,
  John the Ripper, and Hashcat.
- Web challenges with browser snapshots, HTTP fetching, directory discovery,
  SQL injection tooling, and local source audits for dependency-level issues
  such as vulnerable React/Next.js versions. The web agent includes targeted
  playbooks for form exploration, archive-upload issues, JSON/XML API fuzzing,
  mass-assignment checks, source-guided JSON coercion, HTB-style code-runner
  endpoints, and XXE-style CTF patterns.
- Secure-coding challenges where a spawned target exposes editable source and a
  verification endpoint. The secure-coding agent can inspect source through
  editor-style APIs, apply targeted remediation for recognized vulnerable
  patterns, save the patch, and verify the fix for the flag.
- Binary exploitation (pwn) via ret2win discovery (symbol lookup with `nm`/
  `objdump`), cyclic overflow-offset detection, x86-64 stack-alignment gadget
  insertion, and remote payload delivery with pwntools.
- Blockchain smart-contract challenges using Solidity source, HTB-style
  `connection_info` endpoints, JSON-RPC targets, Web3 transactions, and
  deterministic exploit templates for common setup/target patterns such as
  draining challenge contract balances before requesting the flag.
- Local Docker web challenges. Docker execution is opt-in and binds spawned
  targets to `127.0.0.1` before handing them to the web/recon agents.
- Hardware logic challenges involving schematic images, gate/transistor
  descriptions, CSV input tables, and Saleae logic-analyzer captures that need
  Boolean derivation, serial decoding, or output bitstream recovery.
- Forensics tasks involving PDFs, PCAPs, metadata, embedded files, strings,
  recovered artifacts, and live SSH triage for userland-rootkit/library-loader
  anomalies in authorized lab targets.
- Networking tasks using `nmap`, `tshark`, and `scapy` for traffic analysis and
  port scanning.
- OSINT and log-analysis tasks for metadata, domains, authentication events, and
  anomaly patterns.
- Miscellaneous coding/math tasks that benefit from generated Python scripts.

## Repository Layout

```text
agents/       Agent implementations and specialist solvers
core/         Coordinator, routing, challenge models, task queue, results
tools/        Tool wrappers for web, crypto, forensics, network, pwn, and common utilities
config/       System, agent, tool, and environment configuration
challenges/   Example and active challenge JSON files
results/      Generated reports, artifacts, and captured flags
logs/         Runtime logs
tests/        Unit and end-to-end tests
docs/         Architecture and getting-started documentation
```

For a fuller architecture map, see `PROJECT_STRUCTURE.md` and
`docs/architecture/system_overview.md`.

## Requirements

- Python 3.10 or newer.
- Python packages from `requirements.txt`.
- Optional LLM key for LLM-assisted reasoning:
  - `NVAPI_KEY` or `NVAPI_KEYS` for NVIDIA NIM.
  - `ANTHROPIC_API_KEY` for Claude.
  - `OPENAI_API_KEY` for OpenAI.
  - `GOOGLE_API_KEY` for Gemini / Gemini Enterprise Agent Platform API-key testing.
  - Or a local Ollama server for API-free local model routing.

## Installation

```bash
git clone https://github.com/rmjohnson12/CTF_Agents.git
cd CTF_Agents

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

### Pre-flight Check

Before running a challenge, use the diagnostic tool to verify your environment, API keys, and security tools:

```bash
python3 check_setup.py
```

If you plan to use browser-based web tooling, install Playwright's browser runtime:

```bash
python -m playwright install chromium
```

Set your API keys in a `.env` file in the project root:

```bash
NVAPI_KEY=your_nvidia_key_here
```

For multiple NVIDIA NIM keys, use a comma-separated fallback list. If one key
hits a temporary `429` or `503` style failure, the reasoner will try the next
configured key:

```bash
NVAPI_KEYS=first_nvidia_key,second_nvidia_key,third_nvidia_key
```

To prefer a specific LLM provider, set `LLM_PROVIDER`:

```bash
LLM_PROVIDER=nvidia      # nvidia, anthropic, openai, google, or ollama
ANTHROPIC_API_KEY=your_claude_key_here
OPENAI_API_KEY=your_openai_key_here
```

For Google Gemini, the simplest local setup is an API key:

```bash
LLM_PROVIDER=google
GOOGLE_API_KEY=your_google_key_here
GOOGLE_MODEL=gemini-2.5-flash
```

After saving the key, run `python3 check_setup.py` to confirm the provider is
detected before starting a solve.

For Google Cloud Application Default Credentials, authenticate with `gcloud`
and configure the Cloud project:

```bash
gcloud auth application-default login
LLM_PROVIDER=google
GOOGLE_GENAI_USE_VERTEXAI=true
GOOGLE_CLOUD_PROJECT=your-google-cloud-project
GOOGLE_CLOUD_LOCATION=global
```

For local Ollama, start Ollama on your machine and point the agents at its
OpenAI-compatible API:

```bash
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434/v1
OLLAMA_MODEL=llama3.1
```

No API key is required for the default local Ollama setup.

### 🧠 Advanced Autonomous Features
- **Autonomous Specialist Pivoting**: The system now recognizes when a specialist (like `CryptoAgent`) is hitting a wall and will automatically pivot to the `CodingAgent` if a script is provided for analysis.
- **Self-Correcting Coding Agent**: The agent doesn't just write scripts; it debugs them. If an exploit fails, it reads the error logs, reasons about the failure, and iterates on the code autonomously.
- **API Resilience**: Built-in exponential backoff handles transient LLM failures, and NVIDIA NIM can rotate across multiple configured keys.
- **Robust Path Resolution**: Intelligent path normalization handles complex file inputs, including `~/` expansion even when mixed with absolute paths.
- **Source-Only Web Audits**: Local web source folders are inspected for framework and dependency clues, including vulnerable React/Next.js combinations.
- **Source-Guided Web Exploits**: Local source can drive live payloads for
  JSON length/type coercion and palindrome-style validation bugs while ignoring
  fake local flags when a spawned target is available.
- **Web Exploitation Playbooks**: Browser-discovered forms can trigger archive
  upload, JSON/XML API, mass-assignment, XXE, JWT, and interesting-link
  follow-up checks.
- **HTB Code-Runner Playbooks**: Web challenges exposing `/run`-style Python
  execution endpoints can submit compact solvers for coding/math tasks such as
  prime-product key recovery.
- **Hardware Logic Agent**: Hardware/chip/circuit prompts can route to a
  specialist that combines challenge text, local files, images, and CSV tables
  to derive logic and decode output streams. Saleae `.sal` archives are
  inspected for analyzer metadata and decoded as UART 8N1 where applicable.
- **Godot Loader Reversing**: Game-loader challenges can extract Godot PCK AES
  keys from Windows launchers, recover/decompile scripts with GDRE Tools, model
  GDScript obfuscation, and replay loader network requests to retrieve split
  flag material from headers and payload metadata.
- **Blockchain Specialist**: Solidity folders can route to a Web3-backed
  blockchain agent that fetches HTB-style `/connection_info`, connects to the
  challenge RPC endpoint, executes deterministic contract exploits where
  applicable, and retrieves the remote flag. The normal `ask.py` path has been
  validated end to end against a spawned Survival-style smart-contract target.
- **Secure Coding Specialist**: Secure-coding/source-remediation prompts route
  to a dedicated agent that uses editor-style APIs to inspect source, generate
  focused patches for recognized vulnerability patterns, save the updated file,
  and call the target's verification endpoint. The current playbook covers
  legacy flat-file user databases vulnerable to newline/pipe row injection.
- **Run-Scoped Target Allowlisting**: Explicit challenge URLs, IP:port pairs,
  and connection-info endpoints are temporarily allowed only for the active
  solve, preserving outbound network restrictions for unrelated destinations.
- **Reduced Secret Exposure**: Challenge-facing subprocesses run with a minimal
  environment by default so API keys and other host secrets are not inherited by
  LLM-generated scripts or untrusted challenge binaries unless a tool opts in.
- **Opt-In Docker Challenge Runs**: Local Docker web challenge folders can be built and launched when `CTF_AGENTS_ALLOW_DOCKER=1` is set.
- **Live SSH Forensics**: For authorized SSH-based forensics prompts, the
  forensics agent can inspect loader/preload state and shared-library hook
  indicators. Preload bypass searches require an explicit env opt-in.

## 🛠 Prerequisites

- Python 3.10+
- `.env` file with at least one supported LLM key, such as `NVAPI_KEY`,
  `NVAPI_KEYS`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GOOGLE_API_KEY`, or
  `LLM_PROVIDER=ollama` for a local Ollama model.
- Essential security tools: `nmap`, `tshark`, `binwalk`, `john`, `hashcat`.

## 🚀 Quick Start

1. **Check your setup**:
   ```bash
   python3 check_setup.py
   ```

2. **Start the Interactive Solver**:
   ```bash
   python3 ask.py
   ```

3. **Solve a Challenge**:
   You can provide raw instructions or point to files:
   ```text
   > "Who needs AES when you have XOR? The files are in ~/Downloads/challenge.py and ~/Downloads/output.txt"
   ```

   Outbound HTTP/browser access is restricted by `security.allowed_networks` in
   `config/system_config.yaml`. Hosts explicitly present in the challenge
   prompt or JSON are temporarily allowed only for that solve. For additional
   authorized networks, extend the policy for that run:
   ```bash
   CTF_AGENTS_ALLOWED_NETWORKS=TARGET python3 ask.py "Solve this web challenge at http://TARGET:PORT"
   ```

   Source-only web challenges can point directly at a local app folder:
   ```text
   > "Analyze ~/Downloads/web_reactoops/challenge for vulnerable React/Next.js package versions. There is no spawned server."
   ```

   Docker-based web challenges are disabled by default. To allow a local
   container launch, opt in for that command:
   ```bash
   CTF_AGENTS_ALLOW_DOCKER=1 python3 ask.py "Solve this local Docker web challenge in ~/Downloads/web_reactoops"
   ```

   The Docker agent builds the local `Dockerfile`, maps the exposed service to
   `127.0.0.1` on an ephemeral port, publishes that URL, and cleans up the
   container when the coordinator run finishes.

   React2Shell/RSC payload execution is localhost-only by default. For an
   authorized spawned CTF target, explicitly opt in:
   ```bash
   CTF_AGENTS_ALLOW_REMOTE_R2S=1 python3 ask.py "Solve ReactOOPS at http://TARGET:PORT"
   ```

   HTB-style code-runner tasks can be given directly as a spawned target:
   ```bash
   python3 ask.py "Solve Primed for Action at TARGET:PORT. The answer is the product of the two prime numbers."
   ```

   Hardware logic challenge folders can point at local images and CSV files:
   ```bash
   python3 ask.py "Solve this hardware chip challenge. The files are in ~/Downloads/hw_lowlogic"
   ```

   Saleae captures can be passed directly for serial-debugging hardware tasks:
   ```bash
   python3 ask.py "Decode this asynchronous serial debugging capture. Files are in ~/Downloads/debugging_interface_signal.sal"
   ```

   Godot game-loader reversing challenges can include a target service and a
   local extracted challenge folder:
   ```bash
   python3 ask.py "Investigate this compromised game and uncover the two-part flag. Target host TARGET:PORT. Files are in ~/Downloads/rev_gameloader"
   ```

   Blockchain smart-contract challenges can point at a Solidity folder and a
   spawned target:
   ```bash
   python3 ask.py "Solve this blockchain challenge at TARGET:PORT. Files are in ~/Survival"
   ```

   Secure-coding challenges can point directly at a spawned editor/verification
   target:
   ```bash
   python3 ask.py "Secure coding challenge, ip and port are TARGET:PORT"
   ```

   Live SSH forensics prompts can include credentials and a target:
   ```bash
   python3 ask.py "Investigate this SSH forensics target for loader anomalies. Creds: root:hackthebox IP and port are TARGET:PORT"
   ```

   Unknown SSH host keys are rejected by default. For an authorized disposable
   lab target where first-seen host-key trust is acceptable, opt in explicitly:
   ```bash
   CTF_AGENTS_ALLOW_UNKNOWN_SSH_HOST=1 python3 ask.py "Investigate this SSH forensics target. Creds: root:hackthebox IP and port are TARGET:PORT"
   ```

   Read-only loader/rootkit triage runs by default. For authorized CTF/lab
   targets where temporarily disabling `/etc/ld.so.preload` is acceptable, opt
   in to the backup/restore preload-bypass search:
   ```bash
   CTF_AGENTS_ALLOW_SSH_PRELOAD_BYPASS=1 python3 ask.py "Investigate this SSH forensics target for a userland rootkit. Creds: root:hackthebox IP and port are TARGET:PORT"
   ```

## 📂 Project Structure
- `agents/`: Specialist agents (Web, Crypto, Secure Coding, Hardware, Pwn,
  Networking, Coding, etc.).
- `core/`: The "Brain" (LLM Reasoner, Coordinator, Message Broker).
- `tools/`: Wrapped security binaries (TShark, Nmap, John, Hashcat).
- `ask.py`: The main interactive CLI entry point.

## 🧪 Testing
Run the smoke tests to verify the routing logic:
```bash
pytest tests/e2e/test_smoke_prompts.py
```
1. **Interactive Feedback**: If the agent hits a wall, you can provide a "hint" (e.g., "try port 8080" or "the flag is in the EXIF data") and it will resume the solve with the new context.
2. **Persistent Knowledge**: Discovered facts (IPs, credentials, artifacts) are stored in a local Knowledge Base and injected into future reasoning steps.
3. **Networking Specialist**: Deep packet inspection and automated network enumeration are now integrated natively.

`ask.py` will:

1. Convert the instruction into a challenge object.
2. Detect referenced files, URLs, and available local tools.
3. Route the task to a specialist agent.
4. Print the final status, flag if found, and steps taken.

## JSON Challenge Mode

Use `main.py` when you already have a challenge JSON file:

```bash
python3 main.py challenges/templates/example_crypto_base64.json
python3 main.py challenges/templates/example_crypto_base64.json --max-iterations 3
python3 main.py challenges/templates/example_crypto_base64.json --resume
```

Challenge files are dictionaries with fields such as:

```json
{
  "id": "example_crypto_base64",
  "name": "Base64 Warmup",
  "category": "crypto",
  "description": "Decode the provided message and recover the flag.",
  "files": []
}
```

Existing examples live in `challenges/templates/` and simulated active
challenges live in `challenges/active/`.

`--resume` loads `logs/checkpoints/{challenge_id}.json` when present and
continues from the prior history and steps. If no checkpoint exists, the
coordinator starts a fresh run.

## Configuration

The main configuration files are:

- `config/system_config.yaml` for global runtime settings.
- `config/agents_config.yaml` for specialist behavior and priorities.
- `config/tools_config.yaml` for tool paths, timeouts, and enablement.
- `.env.example` for API keys, provider selection, and optional integrations.

Tool availability is detected at runtime where possible, so missing external
tools should degrade specific capabilities rather than preventing all usage.

## Testing

Run the unit suite:

```bash
pytest tests/unit/
```

Run everything:

```bash
pytest
```

The test suite includes coordinator routing, reasoner fallback behavior, tool
wrappers, flag detection utilities, hardware/Saleae decoding paths, Godot
loader reversing helpers, blockchain and secure-coding specialist coverage,
and end-to-end fixtures.

## Runtime Artifacts

Generated outputs are local-only and ignored by git:

- `results/` stores run reports, artifacts, and captured flags.
- `logs/checkpoints/` stores coordinator progress snapshots for resume support.
- `logs/knowledge.db` stores the local knowledge base.
- `logs/performance.db` stores local agent performance history.

To clean local generated output:

```bash
find results -mindepth 1 ! -path 'results/README.md' -exec rm -rf {} +
find logs/checkpoints -mindepth 1 -exec rm -rf {} +
```

## Development Notes

- Add new agents under `agents/specialists/` or `agents/support/`.
- Add command wrappers under `tools/` using the shared tool/result patterns.
- Keep durable fixtures under `challenges/`; keep generated outputs local.
- Prefer adding focused tests in `tests/unit/` for routing, parsing, and wrapper
  behavior before broad end-to-end coverage.

## Security And Ethics

This project is intended for authorized CTF competitions, lab environments,
security research, and education. Do not run it against systems you do not own
or do not have explicit permission to test.

Several boundaries are intentionally conservative: outbound HTTP/browser access
is allowlisted, challenge-declared targets are allowed only during their solve,
unknown SSH host keys are rejected unless explicitly opted in, and local
subprocesses do not inherit the full host environment by default.

## Acknowledgments

Original architecture by TonyZeroArch and myself. Continued development is focused on
practical, iterative CTF automation and agent-assisted security research.

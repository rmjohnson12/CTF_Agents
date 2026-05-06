# CTF_Agents

CTF_Agents is a Python multi-agent system for authorized Capture The Flag
workflows. It routes challenge prompts to specialist agents, runs security tools
through a common wrapper layer, captures observations, and iterates until it can
report a result or explain what blocked progress.

The fastest way to use it is the natural-language CLI in `ask.py`. You describe
the task, the router maps it to the best specialist, and the coordinator manages
the solving loop.

## What It Can Work On

- Reverse engineering tasks involving Python files, executables, binaries, and
  constraint-style password checks.
- Cryptography and password-cracking tasks using hashes, encodings, wordlists,
  John the Ripper, and Hashcat.
- Web challenges with browser snapshots, HTTP fetching, directory discovery, and
  SQL injection tooling.
- Forensics tasks involving PDFs, PCAPs, metadata, embedded files, strings, and
  recovered artifacts.
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
- Optional LLM key:
  - `NVAPI_KEY` for NVIDIA NIM, which is checked first.
  - `OPENAI_API_KEY` for OpenAI fallback.
- Optional command-line security tools, depending on the challenge type:
  - `john`
  - `hashcat`
  - `binwalk`
  - `exiftool`
  - `qpdf`
  - `nmap`
  - `sqlmap`
  - `tshark`
  - `strings`

The system still has heuristic routing when no LLM key is configured, but LLM
configuration improves natural-language mapping and planning.

## Installation

```bash
git clone https://github.com/rmjohnson12/CTF_Agents.git
cd CTF_Agents

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

If you plan to use browser-based web tooling, install Playwright's browser
runtime after installing dependencies:

```bash
python -m playwright install
```

Copy the example environment file if you want LLM-backed routing or optional
external integrations:

```bash
cp config/.env.example .env
```

Then set `NVAPI_KEY` or `OPENAI_API_KEY` in `.env`. The runtime loads `.env` from
the project root.

## Quick Start

Use `ask.py` for natural-language tasks:

```bash
python3 ask.py "Find the password for ~/Downloads/reverse_me.py"
python3 ask.py "Decode this base64 challenge from challenges/templates/example_crypto_base64.json"
python3 ask.py "Analyze suspicious traffic in capture.pcapng and recover the flag"
python3 ask.py "Check http://challenge.local:8080 for common CTF web leaks"
```

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
- `config/.env.example` for API keys and optional integrations.

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
wrappers, flag detection utilities, and end-to-end fixtures.

## Runtime Artifacts

Generated outputs are local-only and ignored by git:

- `results/` stores run reports, artifacts, and captured flags.
- `logs/checkpoints/` stores coordinator progress snapshots for resume support.
- `logs/knowledge.db` stores the local knowledge base.

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

## Acknowledgments

Original architecture by TonyZeroArch and myself. Continued development is focused on
practical, iterative CTF automation and agent-assisted security research.

# Project Structure

This document maps the current tracked repository layout for the CTF_Agents
multi-agent CTF workflow. It is a source-code map, not a list of local runtime
artifacts or optional tools installed on a developer machine.

## Top-Level Layout

```text
CTF_Agents/
├── agents/                 Agent implementations and specialist solvers
├── core/                   Coordination, routing, state, campaign, and reporting
├── tools/                  Python wrappers around external CTF/security tools
├── integrations/           Third-party platform integrations (Hack The Box)
├── challenges/             Example, active, benchmark, and evaluation inputs
├── config/                 YAML defaults and environment templates
├── docs/                   Architecture, guides, security, and integration docs
├── logs/                   Runtime log/checkpoint/DB location; only README tracked
├── reports/                Runtime report output (HTB runs); git-ignored
├── runs/                   Runtime per-challenge working dirs (HTB); git-ignored
├── results/                Runtime result location; only README tracked
├── shared/                 Small shared helper resources
├── tests/                  Unit, integration, e2e, and benchmark tests
├── ask.py                  Natural-language CLI entrypoint
├── main.py                 JSON challenge runner entrypoint
├── campaign.py             Bounded local campaign runner
├── check_setup.py          Local environment and tool diagnostic
├── reporting_server.py     Standalone live-reporting HTTP service launcher
├── simulate.py             Original iterative workflow simulator
├── simulate_v2.py          Expanded simulator scenarios
├── requirements.txt        Python dependency list
└── README.md               Main user-facing project guide
```

## Agents

```text
agents/
├── base_agent.py
├── registry.py             Decorator-based specialist registry
├── coordinator/
│   └── coordinator_agent.py
├── specialists/
│   ├── binary_exploitation/
│   ├── blockchain/
│   ├── cryptography/
│   ├── forensics/
│   ├── hardware_logic/
│   ├── log_analysis/
│   ├── misc/
│   ├── networking/
│   ├── osint/
│   ├── pwn/
│   ├── reverse_engineering/
│   ├── secure_coding/
│   └── web_exploitation/
└── support/
    ├── docker_agent.py
    └── recon_agent.py
```

The coordinator owns the iterative solve loop, specialist selection, history,
checkpointing, and LLM-assisted recovery when normal routing stalls. Specialist
agents handle domain work such as web exploitation, cryptography, reversing,
forensics, hardware logic, log analysis, pwn, networking, OSINT, blockchain,
secure coding, and generated coding/math tasks. Support agents cover local
Docker challenge launch and reconnaissance.

## Core System

```text
core/
├── challenge.py
├── runtime_synthesis.py    Evidence-gated ephemeral runtime tool synthesis
├── campaign/               Bounded multi-challenge campaign runner + stores
├── communication/          Message + broker primitives
├── decision_engine/
│   ├── classifier.py
│   ├── llm_reasoner.py
│   ├── performance_tracker.py
│   └── strategy_selector.py
├── knowledge_base/
│   ├── knowledge_store.py
│   └── solve_trace_store.py
├── reporting/              Live solve-reporting client, store, server, redaction
├── task_manager/
│   ├── task.py
│   └── task_queue.py
└── utils/
    ├── firmware_signatures.py   Content-based artifact routing (e.g. ESP32)
    ├── flag_utils.py
    ├── llm_health.py
    ├── result_manager.py
    ├── security.py              Network allowlist / redaction / safe paths
    ├── session_manager.py
    └── system_checks.py
```

The decision engine combines deterministic routing with optional LLM-backed
analysis and recovery. The performance, knowledge, and solve-trace SQLite
databases are local state (default under `logs/`, overridable via
`CTF_AGENTS_*_DB`) and stay out of version control.

## Tool Wrappers

```text
tools/
├── base_tool.py
├── common/
│   ├── docker_sandbox.py   Isolated container execution for generated solvers
│   ├── elf_utils.py
│   ├── embedding_analogy.py
│   ├── python_tool.py      Backend-selected (docker sandbox / host) executor
│   ├── result.py
│   ├── runner.py
│   └── strings.py
├── crypto/                 hashcat, john
├── forensics/              binwalk, exiftool, qpdf
├── network/               nmap, scapy_tool, tshark
├── pwn/                   angr_tool, headless_ghidra_tool, pwntools_wrapper
└── web/                   browser_snapshot_tool, dirsearch, docker_challenge,
                          http_fetch, react2shell, sqlmap
```

Reversing and pwn helpers live under `tools/pwn/`, `tools/common/`, and the
specialist agents; there is no `tools/reversing/` or `tools/binary/` tree.

## Integrations

```text
integrations/
└── hackthebox/            Hack The Box challenge automation (single account)
    ├── auth.py            Token / cached-session / login handling
    ├── client.py          Defensive v4 API client
    ├── config.py          Endpoint table with confidence notes + env overrides
    ├── models.py          Typed challenge / spawn / attempt / report models
    ├── archive.py         Zip-slip-safe artifact extraction
    ├── challenge_runner.py Discover -> spawn -> download -> solve -> report
    ├── reporting.py       Markdown + JSON run reports
    ├── browser.py         Optional Playwright UI fallback (opt-in)
    └── cli.py             `python -m integrations.hackthebox.cli`
```

See [docs/hackthebox_integration.md](docs/hackthebox_integration.md).

## Challenges

```text
challenges/
├── active/                 Local simulator fixtures and active examples
├── benchmarks/             Benchmark manifest and notes
├── evaluation/             Evaluation challenge JSON and small artifacts
├── templates/              Reusable example challenge JSON files
└── challenge_parser.py
```

Completed challenge outputs are written under runtime result/checkpoint
locations, not a tracked `challenges/completed/` directory.

## Configuration

```text
config/
├── .env.example
├── agents_config.yaml
├── defaults.py
├── system_config.yaml
└── tools_config.yaml
```

The active local `.env` (and an optional git-ignored `.htb.env` for Hack The Box
credentials) is loaded from the project root. The root `.env.example` is the
primary template for local provider keys. NVIDIA fallback keys are configured
with `NVAPI_KEYS`; `NVAPI_KEY` and `NGC_API_KEY` remain supported. Large
dictionaries such as `rockyou.txt` are not bundled.

## Documentation

```text
docs/
├── README.md
├── getting_started.md          Setup and first-run guide
├── guides/getting_started.md   Guided walkthrough (see note below)
├── architecture.md
├── architecture/system_overview.md
├── capabilities.md
├── security_model.md
├── hackthebox_integration.md
├── runtime_tool_synthesis.md
├── live_reporting.md
├── operators_guide.md
├── development.md · testing.md · contributing.md · release_process.md
├── adding_agent.md · adding_tool.md · adding_playbook.md
└── interview_demo.md
```

## Tests

```text
tests/
├── benchmarks/
├── e2e/                    Includes fixtures/ (reverse_me.py, verify_me.py, …)
├── integration/
├── unit/                   Includes unit/hackthebox/ for the HTB integration
├── conftest.py
└── README.md
```

The test suite is pytest-based. `tests/conftest.py` disables live LLM keys and
isolates the knowledge/performance/solve-trace databases per test, so runs stay
deterministic even on a developer machine with credentials configured.

Useful validation commands:

```bash
python3 -m pytest -q
python3 -m pytest -q tests/unit/
python3 check_setup.py
python3 ask.py --help
```

## Runtime State

The following locations accumulate local generated state and are git-ignored:

```text
logs/checkpoints/
logs/*.db
reports/
runs/
results/
.scratch/
.htb.env · .htb_session.json
__pycache__/
.pytest_cache/
```

## Current Scale

At the time this document was refreshed, the tracked tree contained:

- 282 tracked files
- 193 Python files
- 40 Markdown documentation files
- 4 YAML configuration or workflow files

Use `git ls-files` when refreshing this document so it stays aligned with the
committed repository rather than local scratch files.
```

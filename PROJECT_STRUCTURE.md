# Project Structure

This document maps the current tracked repository layout for the CTF_Agents
multi-agent CTF workflow. It is a source-code map, not a list of local runtime
artifacts or optional tools installed on a developer machine.

## Top-Level Layout

```text
CTF_Agents/
├── agents/                 Agent implementations and specialist solvers
├── core/                   Coordination, routing, state, and shared models
├── tools/                  Python wrappers around external CTF/security tools
├── challenges/             Example, active, benchmark, and evaluation inputs
├── config/                 YAML defaults and environment templates
├── docs/                   Architecture, getting-started, and demo docs
├── logs/                   Runtime log/checkpoint location; only README tracked
├── results/                Runtime result location; only README tracked
├── shared/                 Small shared helper resources
├── tests/                  Unit, integration, e2e, and benchmark tests
├── ask.py                  Natural-language CLI entrypoint
├── main.py                 JSON challenge runner entrypoint
├── check_setup.py          Local environment and tool diagnostic
├── simulate.py             Original iterative workflow simulator
├── simulate_v2.py          Expanded simulator scenarios
├── requirements.txt        Python dependency list
└── README.md               Main user-facing project guide
```

## Agents

```text
agents/
├── base_agent.py
├── coordinator/
│   └── coordinator_agent.py
├── specialists/
│   ├── binary_exploitation/
│   ├── cryptography/
│   ├── forensics/
│   ├── hardware_logic/
│   ├── log_analysis/
│   ├── misc/
│   ├── networking/
│   ├── osint/
│   ├── pwn/
│   ├── reverse_engineering/
│   └── web_exploitation/
└── support/
    ├── docker_agent.py
    └── recon_agent.py
```

The coordinator owns the iterative solve loop, specialist selection, history,
checkpointing, and LLM-assisted recovery when normal routing stalls. Specialist
agents handle domain work such as web exploitation, cryptography, reversing,
forensics, hardware logic, log analysis, pwn, networking, OSINT, and generated
coding/math tasks. Support agents cover local Docker challenge launch and
reconnaissance.

## Core System

```text
core/
├── challenge.py
├── communication/
│   ├── message.py
│   └── message_broker.py
├── decision_engine/
│   ├── classifier.py
│   ├── llm_reasoner.py
│   ├── performance_tracker.py
│   └── strategy_selector.py
├── knowledge_base/
│   └── knowledge_store.py
├── task_manager/
│   ├── task.py
│   └── task_queue.py
└── utils/
    ├── flag_utils.py
    ├── result_manager.py
    ├── session_manager.py
    └── system_checks.py
```

The decision engine combines deterministic routing with optional LLM-backed
analysis and recovery. Runtime knowledge and performance databases are local
state and should stay out of version control.

## Tool Wrappers

```text
tools/
├── base_tool.py
├── common/
│   ├── elf_utils.py
│   ├── python_tool.py
│   ├── result.py
│   ├── runner.py
│   └── strings.py
├── crypto/
│   ├── hashcat.py
│   └── john.py
├── forensics/
│   ├── binwalk.py
│   ├── exiftool.py
│   └── qpdf.py
├── network/
│   ├── nmap.py
│   ├── scapy_tool.py
│   └── tshark.py
├── pwn/
│   ├── angr_tool.py
│   ├── headless_ghidra_tool.py
│   └── pwntools_wrapper.py
└── web/
    ├── browser_snapshot_tool.py
    ├── dirsearch.py
    ├── docker_challenge.py
    ├── http_fetch.py
    ├── react2shell.py
    └── sqlmap.py
```

The repository does not contain `tools/reversing/` or `tools/binary/`; reversing
and pwn helpers currently live under `tools/pwn/`, `tools/common/`, and the
specialist agents.

## Challenges

```text
challenges/
├── active/                 Local simulator fixtures and active examples
├── benchmarks/             Benchmark manifest and notes
├── evaluation/             Evaluation challenge JSON and small artifacts
├── templates/              Reusable example challenge JSON files
└── challenge_parser.py
```

There is no tracked `challenges/completed/` directory. Completed challenge
outputs are written under runtime result/checkpoint locations.

## Configuration

```text
config/
├── .env.example
├── agents_config.yaml
├── defaults.py
├── system_config.yaml
└── tools_config.yaml
```

The active local `.env` is loaded from the project root by the reasoner. The
root `.env.example` is the primary template for local provider keys. NVIDIA
fallback keys are configured with `NVAPI_KEYS`, while `NVAPI_KEY` and
`NGC_API_KEY` remain supported.

Tool paths in `config/tools_config.yaml` describe preferred local/system assets.
Large dictionaries such as `rockyou.txt` are not bundled in this repository.

## Shared Resources

```text
shared/
└── scripts/
    └── DumpAnalysis.java
```

The repository currently tracks a small shared Ghidra helper script. It does not
bundle shared payload, exploit, model, or wordlist trees.

## Documentation

```text
docs/
├── README.md
├── architecture/
│   └── system_overview.md
├── guides/
│   └── getting_started.md
└── interview_demo.md
```

There are no tracked `docs/agents/` or `docs/api/` directories at this time.

## Tests

```text
tests/
├── benchmarks/
├── e2e/
├── integration/
├── unit/
├── conftest.py
└── README.md
```

The test suite is pytest-based. `tests/conftest.py` disables live LLM keys by
default so normal test runs stay deterministic even on a developer machine with
provider credentials configured.

Useful validation commands:

```bash
python3 -m pytest -q
python3 -m pytest -q -p no:cacheprovider tests/unit/
python3 check_setup.py
python3 ask.py --help
```

## Runtime State

The following locations are expected to accumulate local generated state:

```text
logs/checkpoints/
logs/*.db
results/
.scratch/
__pycache__/
.pytest_cache/
```

These artifacts are not part of the source structure and should generally stay
ignored unless a test fixture is intentionally added.

## Current Scale

At the time this document was refreshed, the tracked tree contained:

- 184 tracked files
- 129 Python files
- 24 Markdown documentation files
- 4 YAML configuration or workflow files

Use `git ls-tree -r --name-only HEAD` when refreshing this document so it stays
aligned with the committed repository rather than local scratch files.

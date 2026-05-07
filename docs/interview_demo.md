# Interview Demo Script

Use these commands from the repository root. They are ordered from safest to most impressive, so you can stop early if time is tight.

## 1. Show Routing Without Running Tools

```bash
python3 ask.py --plan "Decode the decimal values 67 84 70 123 100 114 121 95 114 117 110 125"
```

What to say:

- `--plan` runs the same parser and routing logic, but exits before invoking agents or external tools.
- This shows the decision layer separately from execution.

## 2. Run a Deterministic Evaluation Fixture

```bash
python3 main.py challenges/evaluation/eval_crypto_decimal_ctfd.json
```

Expected result:

```text
CTF{dry_run}
```

What to say:

- The challenge parser normalizes CTFd-style JSON into the internal challenge shape.
- The coordinator routes to the crypto specialist using heuristics or an LLM-backed reasoner.

## 3. Run a File-Based Log Fixture

```bash
python3 main.py challenges/evaluation/eval_log_webaccess.json
```

Expected result:

```text
CTF{log_4n4lysis}
```

What to say:

- This exercises parser file resolution, specialist routing, and artifact analysis.
- CI tracks the fixture log explicitly so GitHub Actions tests match local behavior.

## 4. Show Recon Planning

```bash
python3 ask.py --plan "Enumerate and fingerprint http://127.0.0.1:8080 before exploiting it"
```

What to say:

- Explicit recon language routes to `recon_agent`.
- Recon is a support agent: it gathers services, headers, technologies, and paths for downstream specialists.

## 5. Show The Full Test Gate

```bash
python3 -m pytest -q
```

What to say:

- The project has unit, integration, e2e, parser, smoke prompt, and evaluation fixture coverage.
- GitHub Actions runs the same test suite on push.

## Short Architecture Story

The system has four layers:

- CLI/parser: turns natural language or JSON exports into a normalized challenge.
- Reasoner/coordinator: chooses the next agent/tool, tracks history, checkpoints progress, and injects prior knowledge.
- Agents/tools: specialists solve crypto, web, forensics, logs, reverse engineering, networking, and support recon.
- Persistence/testing: KnowledgeStore, PerformanceTracker, checkpoints, e2e fixtures, and CI keep the workflow reproducible.

# Agent Benchmark Set

This directory contains deterministic regression benchmarks for the CTF agent
system. The goal is to capture small, known-good challenge patterns so agent
changes can be measured instead of judged by memory.

Run the benchmark suite with:

```bash
pytest tests/benchmarks
```

## Manifest Format

Benchmarks live in `manifest.json`.

- `mode: "solve"` runs the coordinator and expects a solved result.
- `mode: "route"` checks heuristic routing only.
- `generated_files` creates small temporary artifacts during the test run.
- `requires` lists external commands such as `strings`; cases are skipped when
  the command is unavailable.

When adding a new case, prefer the smallest fixture that exercises the behavior:
one challenge idea, one expected route or flag, and no live network dependency.

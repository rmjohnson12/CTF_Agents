# Implementation Guide

CTF_Agents is implemented and in active use. This guide is a short map of *how*
the pieces fit together and where to make changes. (It replaces the original
pre-build phase roadmap, which no longer matched the code.)

## How a solve flows

1. **Entry** — `ask.py` (natural language) or `main.py` (challenge JSON) build a
   coordinator via `main.build_coordinator()` and call `solve_challenge()`.
2. **Route** — `core/decision_engine/` classifies the challenge and picks a
   specialist. Routing is content-first where possible (`core/utils/firmware_signatures.py`),
   then LLM-assisted planning (`llm_reasoner.py`), with performance/solve-trace
   hints (`performance_tracker.py`, `knowledge_base/solve_trace_store.py`).
3. **Solve** — the `agents/coordinator/coordinator_agent.py` loop dispatches to a
   specialist under `agents/specialists/<category>/`, which runs bounded tools
   from `tools/` (and, when needed, container-isolated generated scripts via
   `tools/common/docker_sandbox.py`).
4. **Record & report** — results, checkpoints, knowledge, and solve traces are
   persisted (SQLite under `logs/`); optional live reporting lives in
   `core/reporting/`.

## Where to make common changes

| Goal | Start here |
|------|------------|
| Add a specialist agent | `agents/specialists/`, register via `agents/registry.py` — see [docs/adding_agent.md](docs/adding_agent.md) |
| Add a tool wrapper | `tools/` — see [docs/adding_tool.md](docs/adding_tool.md) |
| Add a solver playbook | the relevant specialist — see [docs/adding_playbook.md](docs/adding_playbook.md) |
| Change routing/classification | `core/decision_engine/` |
| HTB automation | `integrations/hackthebox/` — see [docs/hackthebox_integration.md](docs/hackthebox_integration.md) |
| Security/sandbox policy | `core/utils/security.py`, `tools/common/docker_sandbox.py` — see [docs/security_model.md](docs/security_model.md) |

## Reference docs

- Repository map: [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)
- Architecture: [docs/architecture.md](docs/architecture.md)
- Capabilities: [docs/capabilities.md](docs/capabilities.md)
- Testing: [docs/testing.md](docs/testing.md)

Every change should ship with focused tests (`python3 -m pytest -q`) and a docs
update when behavior or layout changes.

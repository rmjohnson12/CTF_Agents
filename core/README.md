# Core System Components

Core infrastructure that coordinates agents, routes challenges, persists state,
and reports results.

## Components

### decision_engine/
Challenge classification and routing: `classifier.py`, `strategy_selector.py`,
`llm_reasoner.py` (LLM-backed analysis/planning with provider failover), and
`performance_tracker.py` (per-agent/category solve-rate routing hints).

### knowledge_base/
SQLite-backed state: `knowledge_store.py` (per-challenge facts) and
`solve_trace_store.py` (compact successful-solve traces and technique
fingerprints, no raw flags).

### task_manager/
`task.py` and `task_queue.py` — priority task queue for the coordinator loop.

### communication/
`message.py` and `message_broker.py` — in-process message passing.

### campaign/
Bounded multi-challenge campaign runner and attempt stores (`runner.py`,
`attempt_store.py`, `providers.py`).

### reporting/
Optional live solve reporting: `client.py`, `server.py`, `store.py`, `models.py`,
`redaction.py`.

### runtime_synthesis.py
Evidence-gated composition of small ephemeral declarative tools (no host code
execution). See [../docs/runtime_tool_synthesis.md](../docs/runtime_tool_synthesis.md).

### utils/
Shared helpers: `security.py` (network allowlist / redaction / safe paths),
`flag_utils.py`, `firmware_signatures.py` (content-based routing), `llm_health.py`,
`result_manager.py`, `session_manager.py`, `system_checks.py`.

## Runtime state

The knowledge, performance, and solve-trace databases default to `logs/` and are
local, git-ignored state (overridable via `CTF_AGENTS_*_DB`). They must stay out
of version control.

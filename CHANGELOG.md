# Changelog

Notable changes per release. Versions follow the tag on the default branch and
`core/_version.py`, which is the single place the version is declared.

## 2.6.0 — 2026-08-24

The first release since `v2.5` (tagged 2026-05-05), covering 138 commits of
specialist work plus a packaging, CI, and disclosure pass.

### Packaging

- Added `pyproject.toml`. The project is pip-installable, with a real version,
  console entry points, and optional dependency extras.
- New commands on `PATH`: `ctf-agents`, `ctf-agents-run`, `ctf-agents-campaign`,
  `ctf-agents-check`, `ctf-agents-report`. The repo-root scripts still work.
- Split optional dependencies into `[lattice]`, `[blockchain]`, `[reversing]`,
  `[forensics]`, `[ml]`, plus `[all]`, `[test]`, `[lint]`, and `[dev]`.
- Removed nine dependencies that no module imports: `beautifulsoup4`, `click`,
  `cryptography`, `pandas`, `python-magic`, `rich`, `selenium`, `sentry-sdk`,
  and `structlog`.
- Relaxed `cysignals>=1.12.6` to `>=1.12.5`. The old floor was Python 3.12+
  only, which made the lattice stack uninstallable on 3.10 and 3.11.
- Raised stale floors: `anthropic>=0.40`, `openai>=1.40`, `pydantic>=2.7`.
- Added `uv.lock` for reproducible installs (`uv sync --all-extras`).
- `requirements.txt` is now a compatibility shim resolving to `-e .[all]`.

### Continuous integration

- Replaced the single-job workflow with `lint`, `test`, and `build` jobs.
- Test matrix across Python 3.10, 3.11, 3.12, and 3.13.
- Added `ruff` and `mypy` (scoped to `core/`) as blocking checks.
- Enabled the `pytest-cov` coverage that was already a dependency but unused.
- Added pip caching, concurrency cancellation, and an sdist/wheel build check.

### Security

- Added `SECURITY.md`: private disclosure via GitHub advisories, and an explicit
  in-scope/out-of-scope boundary for an offensive-security tool.
- Added an *Untrusted content and prompt injection* section to
  `docs/security_model.md`, stating the treat-as-data position, the structural
  controls behind it, and its known limits.

### Fixes

- `coding_agent`: bound `last_error` and `last_stdout` before the retry loop.
  Both were read at the top of a retry iteration but only assigned further down
  the body.
- `forensics_agent`: bound the loop variable captured by the `substitute`
  closure in Powershell format-string recovery.
- `core/reporting/server.py`, `integrations/hackthebox/auth.py`: chained
  exceptions so the original cause survives.
- `core/runtime_synthesis.py`: separated the `subprocess` result variable from
  the `HttpFetchResult` one it shadowed.
- `core/utils/security.py`: corrected the `_ip_matches_allowed` annotation to
  the concrete address types callers pass.
- Handled `Optional[int]` from `sqlite3` `lastrowid` in the trace, attempt, and
  reporting stores.
- Removed dead code: the unread `replayed_any` flag in `blockchain_agent` and
  several unused locals across specialists.

### Configuration and documentation

- Deleted `config/.env.example`. It had drifted from the root template on
  `LLM_PROVIDER` and documented 26 variables no code reads, including a Postgres,
  Redis, and RabbitMQ layer that does not exist. The project-root `.env.example`
  is the only template.
- Consolidated the version to `core/_version.py`. It was previously stated as
  `1.0.0` in a root `__init__.py` and in `config/system_config.yaml` while the
  tags read `v2.5`.
- Removed the stray root `__init__.py` that made the repository itself a package.
- Retired `pytest.ini`; pytest configuration lives in `pyproject.toml`.
- Cleared the executable bit from 85 files that are not scripts.

### Specialists since v2.5

Quantum protocol, industrial control, AI/ML prompt-security, and secure-coding
specialists; a decorator-based agent registry; evidence-gated runtime tool
synthesis with compute and disassembly operations; foreign-architecture ELF
execution and remote ARM emulation; Hack The Box automation; configurable live
solve reporting; provider failover across NVIDIA, Anthropic, OpenAI, Google, and
Ollama; and crypto recovery for shared-prime RSA, redacted PEM, Boolean
polynomial, two-round AES oracle, and same-block entropy vault challenges.

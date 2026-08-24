# Documentation

Documentation for the CTF Multi-Agent System. Every file referenced below exists
in this directory; keep this index in sync when adding or removing docs.

## Getting started

- [getting_started.md](getting_started.md) — short setup + first-run quickstart
- [guides/getting_started.md](guides/getting_started.md) — longer install/usage walkthrough
- [operators_guide.md](operators_guide.md) — running and operating the system

## Architecture & capabilities

- [architecture.md](architecture.md) — component and control-flow overview
- [architecture/system_overview.md](architecture/system_overview.md) — high-level system design
- [capabilities.md](capabilities.md) — per-category solver coverage
- [runtime_tool_synthesis.md](runtime_tool_synthesis.md) — evidence-gated ephemeral tool composition

## Security & integrations

- [security_model.md](security_model.md) — network allowlists, sandboxing, redaction, opt-ins
- [hackthebox_integration.md](hackthebox_integration.md) — Hack The Box challenge automation
- [live_reporting.md](live_reporting.md) — progress-event schema, REST routes, SSE, deployment

## Contributing & process

- [development.md](development.md) — local development workflow
- [testing.md](testing.md) — test layout and how to run the suite
- [contributing.md](contributing.md) — contribution guidelines
- [adding_agent.md](adding_agent.md) — add a new specialist agent
- [adding_tool.md](adding_tool.md) — add a new tool wrapper
- [adding_playbook.md](adding_playbook.md) — add a solver playbook
- [release_process.md](release_process.md) — release checklist
- [interview_demo.md](interview_demo.md) — guided demo script

See also [PROJECT_STRUCTURE.md](../PROJECT_STRUCTURE.md) for the repository map.

## Documentation standards

- Markdown for all docs, with runnable code examples where useful.
- Keep docs in sync with code; review doc changes alongside code in PRs.
- Every relative link and referenced filename must point at a file that exists.

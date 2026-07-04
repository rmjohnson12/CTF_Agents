# Agents Directory

Agent implementations for the hierarchical multi-agent CTF system. Specialists
are registered via `agents/registry.py` and selected by the coordinator.

## Coordinator

`coordinator/coordinator_agent.py` orchestrates a solve: it analyzes the
challenge, routes to a specialist, runs the iterative solve loop with history and
checkpointing, and performs LLM-assisted recovery when routing stalls.

## Specialists

Under `specialists/`, one package per category:

- **web_exploitation** — web vulnerabilities, API/JS discovery, auth bypass
- **cryptography** — encoding/classical ciphers, RSA, DH oracles, hash cracking
- **reverse_engineering** — binary analysis and constraint recovery
- **pwn** / **binary_exploitation** — exploitation and exploit development
- **forensics** — memory/disk/pcap/artifact analysis
- **hardware_logic** — logic captures, ESP32 firmware, raw-TCP diagnostics
- **log_analysis** — log triage and event correlation
- **blockchain** — smart-contract interaction and attacker-contract deployment
- **secure_coding** — source-patch remediation with verification
- **networking** — protocol and packet work
- **osint** — open-source intelligence gathering
- **misc** — generated coding/math solvers

## Support

`support/` provides auxiliary agents: `docker_agent.py` (local Docker challenge
launch) and `recon_agent.py` (reconnaissance/enumeration).

## Agent contract

Each specialist implements challenge analysis, a `solve_challenge()` entry point
that runs bounded tools/playbooks, flag validation, and result reporting. See
[docs/adding_agent.md](../docs/adding_agent.md).

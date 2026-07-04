# Capabilities

Capabilities are grouped by system rather than by individual challenge exploit.
Implementation-specific playbooks remain close to their specialist code and
tests.

## Routing and reasoning

- Natural-language and challenge-JSON classification
- Evidence-led direct dispatch for high-confidence categories
- LLM-assisted planning and failure review
- Performance and successful-trace routing hints
- Iterative fallback with duplicate-action suppression
- Evidence-bound runtime composition for previously unseen HTTP/artifact workflows

## Tool execution

- HTTP/browser discovery, SQL tooling, directory discovery, and React/RSC probes
- Binary inspection, strings, disassembly helpers, and controlled subprocesses
- ARM-architecture wordplay detection and bounded A32 emulation for remote register protocols
- Hash cracking, packet analysis, metadata extraction, Docker, SSH, and Web3
- Explicit network and host-execution policy checks
- Isolated container execution backend for model-generated solver scripts
  (no network, read-only mounts, resource/time limits) via `CTF_AGENTS_SANDBOX=docker`
- Ephemeral HTTP/read/regex/decode/JSON tools synthesized without host code execution

## Artifact processing

- Source trees, archives, PDFs, PCAPs, images, firmware, executables, and logs
- Encoded artifact recovery and flag extraction
- Saleae UART decoding and ESP32 flash-image parsing
- Bounded raw-TCP Forth diagnostic discovery with dictionary-gated command execution
- Result redaction and bounded persistence

## Exploit and solution generation

- Web authentication, source-guided API, upload, session, and dependency paths
- General API option/command enumeration (discover endpoints from client JS,
  enumerate option lists, submit secret/hidden options for a flag)
- Evidence-gated URL-to-PDF chains spanning duplicate-parameter parser mismatches,
  formatted-history disclosure, and JWT authorization
- Reverse-engineering strategies for local artifacts and authorized remote machine-code streams
- Cryptographic decoding and constraint recovery, including source-backed
  repeating-XOR known-prefix recovery and small-subgroup Diffie-Hellman oracle
  discrete-log recovery
- Word-embedding analogy recovery with raw vector offsets and ASCII/NFKC filtering
- Secure-coding patches and deterministic code-runner submissions
- Smart-contract interaction and authorized remote challenge workflows
- Interface-gated EVM lifecycle transactions with on-chain `isSolved()` verification
- Source-driven attacker-contract compilation and deployment for exploits that
  require a contract caller (e.g. `tx.origin` access-control gates)
- Credentialed live-SSH loader/rootkit triage with explicitly gated host trust
  and backup/restore `/etc/ld.so.preload` bypass

## Learning and reporting

- Checkpoint resume
- Successful solve-trace storage without raw flags
- Runtime technique fingerprints and technique-based prior-solve retrieval
- Technique-bearing solve hints delivered back to specialists on later runs
- JSON run reports and campaign SQLite ledgers
- Repeatable benchmark summaries

## Specialist categories

Current specialists cover web, cryptography, reverse engineering, pwn,
forensics, hardware, blockchain, secure coding, networking, OSINT, log analysis,
and miscellaneous coding. See each module under `agents/specialists/` and its
tests for the current detailed playbook inventory.

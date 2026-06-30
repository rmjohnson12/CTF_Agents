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

## Tool execution

- HTTP/browser discovery, SQL tooling, directory discovery, and React/RSC probes
- Binary inspection, strings, disassembly helpers, and controlled subprocesses
- Hash cracking, packet analysis, metadata extraction, Docker, SSH, and Web3
- Explicit network and host-execution policy checks

## Artifact processing

- Source trees, archives, PDFs, PCAPs, images, firmware, executables, and logs
- Encoded artifact recovery and flag extraction
- Saleae UART decoding and ESP32 flash-image parsing
- Result redaction and bounded persistence

## Exploit and solution generation

- Web authentication, source-guided API, upload, session, and dependency paths
- Reverse-engineering and binary-exploitation strategies
- Cryptographic decoding and constraint recovery
- Word-embedding analogy recovery with raw vector offsets and ASCII/NFKC filtering
- Secure-coding patches and deterministic code-runner submissions
- Smart-contract interaction and authorized remote challenge workflows

## Learning and reporting

- Checkpoint resume
- Successful solve-trace storage without raw flags
- JSON run reports and campaign SQLite ledgers
- Repeatable benchmark summaries

## Specialist categories

Current specialists cover web, cryptography, reverse engineering, pwn,
forensics, hardware, blockchain, secure coding, networking, OSINT, log analysis,
and miscellaneous coding. See each module under `agents/specialists/` and its
tests for the current detailed playbook inventory.

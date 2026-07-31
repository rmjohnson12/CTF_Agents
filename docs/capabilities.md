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
- Bounded OOXML external-relationship inspection for live Office artifacts,
  including Base64 script recovery and PowerShell format-expression deobfuscation
- Source-gated PHP webshell traffic recovery from PCAP streams, including keyed
  compressed/XOR decoding and exfiltrated KeePass database inspection
- Result redaction and bounded persistence

## Exploit and solution generation

- Web authentication, source-guided API, upload, session, and dependency paths
- General API option/command enumeration (discover endpoints from client JS,
  enumerate option lists, submit secret/hidden options for a flag)
- Evidence-gated URL-to-PDF chains spanning duplicate-parameter parser mismatches,
  formatted-history disclosure, and JWT authorization
- Reverse-engineering strategies for local artifacts and authorized remote machine-code streams
- ELF-header-driven execution routing: a challenge binary the host cannot run
  natively may be executed, after explicit Docker authorization, from a staged
  copy inside a locked-down container started with the `--platform` its header
  implies; an undeliverable payload is reported once with both architectures
  named instead of retried across an offset ladder
- Bounded quantum-protocol analysis and deterministic Oathbinding recovery using
  Bell-state correlations and deferred Z/X-basis measurement, with network
  allowlisting, response validation, and round/strand limits
- Bounded adversarial AI/ML prompt-leaking workflows with verified HTTP client
  contracts, JWT/CSRF session progression, model-output-derived candidates, and
  authoritative verification-endpoint flag acceptance
- Evidence-gated ICS/OT recovery for PLC ladder-logic processes, including
  bounded Modbus RTU single-coil writes and verified process-state transitions
- Cryptographic decoding and constraint recovery, including source-backed
  repeating-XOR known-prefix recovery and small-subgroup Diffie-Hellman oracle
  discrete-log recovery
- Redacted-PEM key recovery: rebuilds the base64 grid of a partially masked
  PKCS#1 private key, walks the DER with sub-byte precision to recover the
  modulus and a prime's leading bits, then factors the modulus with Coppersmith
- Source-gated shared-prime RSA recovery when a second same-size modulus is
  obscured by a linear multiple of the first: GCD factor recovery, bounded
  modulus disambiguation, and multi-part plaintext reconstruction
- Bounded chosen-plaintext recovery for source-identified two-round AES-like
  encrypted-save oracles, including reversible key expansion and winning-save
  forgery within a 13-query budget
- Source-backed Boolean-polynomial linearization over GF(2), bit-packed Gaussian
  elimination, and bounded nullspace enumeration for AES key recovery
- Word-embedding analogy recovery with raw vector offsets and ASCII/NFKC filtering
- Secure-coding patches and deterministic code-runner submissions
- Interactive coding-instance discovery from page content, `/run`-style grader
  submission, deterministic weighted-graph shortest-path solving, and optional
  LLM synthesis corrected by bounded grader feedback
- Smart-contract interaction and authorized remote challenge workflows
- Interface-gated EVM lifecycle transactions with on-chain `isSolved()` verification
- Source-driven attacker-contract compilation and deployment for exploits that
  require a contract caller (e.g. `tx.origin` access-control gates)
- Source-gated same-block entropy mirroring for EVM vaults whose private unlock
  key is derived from caller-visible block values and a constantized secret
- Source-detected pre-0.8 ERC20 balance underflow, bounded token/shop discovery,
  signed purchase transactions, and on-chain solve verification
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

Current specialists cover web, cryptography, quantum protocols, adversarial
AI/ML, industrial
control systems and operational technology, reverse
engineering, pwn, forensics, hardware, blockchain, secure coding, networking,
OSINT, log analysis, and miscellaneous coding. See each module under
`agents/specialists/` and its tests for the current detailed playbook inventory.

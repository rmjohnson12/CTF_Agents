# Tools Directory

Python wrappers around external CTF/security tools and in-process helpers used by
the specialist agents. Each wrapper subclasses `tools/base_tool.py` and returns a
structured `ToolResult`.

## Categories

### common/
General-purpose helpers: `python_tool.py` (backend-selected script executor),
`docker_sandbox.py` (isolated container execution for generated solvers),
`runner.py` (bounded subprocess runner), `elf_utils.py`, `strings.py`,
`embedding_analogy.py`, and `result.py`.

### crypto/
Cryptography tooling: `john.py`, `hashcat.py` (hash cracking).

### forensics/
Digital forensics: `binwalk.py`, `exiftool.py`, `qpdf.py`.

### network/
Network analysis: `nmap.py`, `tshark.py`, `scapy_tool.py`.

### pwn/
Binary exploitation / reversing helpers: `pwntools_wrapper.py`,
`angr_tool.py`, `headless_ghidra_tool.py`.

### web/
Web exploitation: `http_fetch.py`, `browser_snapshot_tool.py`, `dirsearch.py`,
`sqlmap.py`, `react2shell.py`, `docker_challenge.py`.

There is no `tools/reversing/` or `tools/binary/` directory — reversing and pwn
helpers live under `tools/pwn/`, `tools/common/`, and the specialist agents.

## Conventions

Each tool wrapper should have clear input/output types, bounded execution with
timeouts, error handling that never crashes the caller, and (where it touches the
network or the host) explicit policy checks via `core/utils/security.py`.

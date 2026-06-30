# Security Model

CTF_Agents treats challenge metadata and artifacts as untrusted input.

## Network boundaries

Remote hosts must be approved through `CTF_AGENTS_ALLOWED_NETWORKS` or trusted
configuration. URLs embedded in challenge JSON cannot authorize themselves.
Hostnames are resolved and checked against the allowlist before use.

## Process and environment isolation

Tool subprocesses receive a reduced environment by default. Generated Python
is not executed on the host unless
`CTF_AGENTS_ALLOW_HOST_PYTHON_EXECUTION=1` is explicitly set. Prefer static
analysis or an isolated challenge container.

## Docker

Local Docker challenge execution is opt-in with
`CTF_AGENTS_ALLOW_DOCKER=1`. Spawned ports bind to loopback, and cleanup must be
attempted and reported even after failures.

## SSH and live systems

SSH workflows are limited to explicitly supplied, authorized targets. The
system does not silently relax host or network policy based on challenge data.

## Raw TCP diagnostic interpreters

The Forth diagnostic workflow is enabled only when the challenge description
explicitly identifies Forth and supplies a host and port. Before opening the
socket, the hardware specialist applies the same host allowlist used by other
remote agents.

The workflow is deliberately constrained:

- it selects the documented diagnostic menu and enumerates `words` first;
- it requires a standalone `system` dictionary word before execution;
- it executes only `cat` against three fixed flag paths;
- socket reads have deadlines and a 128 KiB response limit; and
- it never turns challenge text into an arbitrary shell command.

Failure at any evidence or policy gate returns an attempted result with the
reason recorded; it does not fall through to unrestricted command execution.

## Artifacts and secrets

Reports, messages, knowledge stores, and campaign ledgers redact sensitive
keys. Raw browser cookies and storage are excluded unless
`CTF_AGENTS_CAPTURE_SENSITIVE_ARTIFACTS=1` is explicitly enabled. Raw flags are
hashed where retained for learning or campaign history.

## Specialized opt-ins

- Remote React/RSC execution: `CTF_AGENTS_ALLOW_REMOTE_R2S=1`
- Host Python execution: `CTF_AGENTS_ALLOW_HOST_PYTHON_EXECUTION=1`
- Local Docker challenge runs: `CTF_AGENTS_ALLOW_DOCKER=1`
- Sensitive browser artifacts: `CTF_AGENTS_CAPTURE_SENSITIVE_ARTIFACTS=1`

These controls do not replace authorization. They only enable a bounded
capability after the operator has confirmed scope.

# Security Model

CTF_Agents treats challenge metadata and artifacts as untrusted input.

## Network boundaries

Remote hosts must be approved through `CTF_AGENTS_ALLOWED_NETWORKS` or trusted
configuration. URLs embedded in challenge JSON cannot authorize themselves.
Hostnames are resolved and checked against the allowlist before use. Remote ARM
instruction streams are also allowlist-gated and execute only inside a fresh,
instruction-limited Unicorn emulator rather than as host code.

## Process and environment isolation

Tool subprocesses receive a reduced environment by default. Generated Python
is not executed on the host unless
`CTF_AGENTS_ALLOW_HOST_PYTHON_EXECUTION=1` is explicitly set. Prefer static
analysis or an isolated challenge container.

## Runtime tool synthesis

Runtime synthesis does not generate or execute Python, shell commands, package
installers, or persistent plugins. After ordinary specialists and recovery
stall, the model may propose one ephemeral declarative tool containing at most
12 operations: same-origin HTTP requests, reads restricted to supplied
artifacts, bounded regex extraction, base64/hex/URL decoding, and JSON lookup.

The proposal must quote evidence already present in the challenge trace. The
validator rejects invented evidence, cross-origin requests, redirects, unsafe
regex constructs, oversized specifications, unknown variables, unsupported
operations, and artifact path escapes. Sensitive context is redacted before it
is sent to the model, and synthesized tools are not registered or persisted as
executable code.

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

## Live reporting

Live reporting is disabled unless `CTF_AGENTS_REPORTING_URL` is configured.
Outbound events redact secret-bearing artifact keys and flags embedded in text.
The reporting service stores final flags only when both sender and server opt in.

Ingestion and read credentials are separate. Static frontend code must never
contain the write token. Cross-origin browser access is denied unless the exact
origin is configured, public timeline reads are opt-in, and non-loopback server
binds require an ingestion token. See [live_reporting.md](live_reporting.md).

## Specialized opt-ins

- Remote React/RSC execution: an explicit `CTF_AGENTS_ALLOWED_NETWORKS` match,
  or the legacy `CTF_AGENTS_ALLOW_REMOTE_R2S=1` override
- Host Python execution: `CTF_AGENTS_ALLOW_HOST_PYTHON_EXECUTION=1`
- Local Docker challenge runs: `CTF_AGENTS_ALLOW_DOCKER=1`
- Sensitive browser artifacts: `CTF_AGENTS_CAPTURE_SENSITIVE_ARTIFACTS=1`

These controls do not replace authorization. They only enable a bounded
capability after the operator has confirmed scope.

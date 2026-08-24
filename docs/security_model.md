# Security Model

CTF_Agents treats challenge metadata and artifacts as untrusted input.

## Untrusted content and prompt injection

Challenge descriptions, file artifacts, HTTP response bodies, disassembly
listings, and Git history are all written by the challenge author, and all of
them reach the recovery model as observations. Assume every one of them contains
text addressed to the model.

The stance is that observed content is **data, never instruction**. The system
does not rely on the model recognizing or refusing an injected instruction.
Containment is structural: the model has no capability that an injected
instruction could usefully redirect.

- **No direct action.** The model never executes anything. Its only outward
  product is a declarative specification of at most 12 operations drawn from a
  fixed allowlist (same-origin HTTP, reads of supplied artifacts, bounded regex,
  base64/hex/URL decode, JSON lookup, and sandboxed compute). It cannot emit
  shell commands, install packages, or register a persistent tool.
- **Evidence must be real.** Every proposal has to cite trace facts, and the
  validator checks each citation against the observed trace, rejecting the
  proposal outright when a citation is not present (`core/runtime_synthesis.py`,
  `_validate_spec` / `_evidence_supported`). Text invented to justify an action
  fails the gate.
- **Targets cannot authorize themselves.** A URL that appears inside artifact
  text still has to satisfy the same-origin rule and the host allowlist. See
  [Network boundaries](#network-boundaries).
- **Paths cannot escape.** Reads resolve only to explicitly supplied artifacts;
  path escapes are rejected.
- **Generated code is contained, not trusted.** Model-authored Python runs only
  in the fail-closed Docker backend with `--network none`, or not at all. Host
  execution requires a separate, explicit operator opt-in.
- **Flags must be earned.** A run is marked solved only when a flag pattern is
  found in *executed output* (`core/runtime_synthesis.py`). A model that simply
  asserts a flag — because an artifact told it to — cannot mark a run solved.
- **Context is bounded and redacted.** Challenge data, the last 6 history
  entries, and the last 60 steps are passed through `redact_sensitive_data`
  before they reach a provider (`core/decision_engine/llm_reasoner.py`).

Known limits, stated plainly:

- There is no prompt-level instruction telling the model to disregard directives
  found in artifacts. The guarantees above are structural, not persuasive, and
  should be read that way.
- Injected text can still influence *which* allowed operation gets chosen. It
  can waste turns or steer analysis down a dead end. It cannot widen the
  allowlist, reach a new host, read an unsupplied path, or manufacture a flag.
- Redaction is pattern-based. It reduces incidental secret exposure to a
  provider; it is not a guarantee against a determined exfiltration attempt
  embedded in challenge text.

Report anything that crosses one of these boundaries through
[SECURITY.md](../SECURITY.md).

## Network boundaries

Remote hosts must be approved through `CTF_AGENTS_ALLOWED_NETWORKS` or trusted
configuration. URLs embedded in challenge JSON cannot authorize themselves.
Hostnames are resolved and checked against the allowlist before use. Remote ARM
instruction streams are also allowlist-gated and execute only inside a fresh,
instruction-limited Unicorn emulator rather than as host code.

## Process and environment isolation

Tool subprocesses receive a reduced environment by default. Model-generated
Python is never executed on the host implicitly. There are two opt-in backends,
selected by `CTF_AGENTS_SANDBOX`:

- `docker` (recommended): each generated script runs in a throwaway container
  with no network (`--network none`), a read-only root filesystem plus a small
  `noexec` tmpfs, challenge artifacts mounted read-only at their original paths,
  hard memory/CPU/PID limits, all Linux capabilities dropped,
  `no-new-privileges`, a non-root uid, and a strict wall-clock timeout after
  which the container is force-removed.
- host execution: only when `CTF_AGENTS_ALLOW_HOST_PYTHON_EXECUTION=1` is
  explicitly set. This runs arbitrary generated code directly on the machine and
  should be avoided in favor of the Docker backend.

Sandbox network egress is **fail-closed and currently unsupported**. Requests
for networked generated-code execution are rejected and the container remains
on `--network none`. A future sidecar must enforce destination policy at the
network layer before this can be enabled safely.

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
attempted and reported even after failures. The same opt-in controls isolated
execution of foreign-architecture challenge binaries.

## Cross-architecture binary execution

A challenge binary the host cannot execute natively may be run through
`tools/common/cross_arch_runner.py`, which mounts it read-only into a throwaway
container started with `--platform` derived from the binary's ELF header. The
threat model is stronger than the generated-solver sandbox — this is an
untrusted third-party executable rather than model-authored Python — so the
container keeps the same restrictions and adds nothing back: `--network none`,
`--read-only` root with a `noexec,nosuid` tmpfs, all capabilities dropped,
`no-new-privileges`, a non-root uid, memory and PID caps, `--rm`, and a strict
timeout followed by forced removal. There is no flag that enables networking on
this path.

The runner is default-deny: it does not probe or invoke the container runtime
unless `CTF_AGENTS_ALLOW_DOCKER=1` is set for the authorized run. It copies the
binary into a private temporary staging directory and adjusts only that copy's
permissions, leaving the original artifact unchanged.

When no container runtime is reachable, the agent reports that it cannot deliver
a local payload and stops. It does not fall back to executing the binary on the
host.

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
- Local Docker challenge and foreign-ELF runs: `CTF_AGENTS_ALLOW_DOCKER=1`
- Sensitive browser artifacts: `CTF_AGENTS_CAPTURE_SENSITIVE_ARTIFACTS=1`

These controls do not replace authorization. They only enable a bounded
capability after the operator has confirmed scope.

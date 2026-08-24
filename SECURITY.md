# Security Policy

CTF_Agents is offensive-security tooling. It executes untrusted challenge
binaries, runs model-authored code, and talks to hosts you point it at. Some
behavior that looks alarming is the product working as designed, and some is
not. This document draws that line and tells you how to report the second kind.

## Reporting a vulnerability

**Do not open a public issue for a security report.**

Use GitHub's private vulnerability reporting: go to the repository's
**Security** tab and choose **Report a vulnerability**. That opens a private
advisory visible only to you and the maintainers.

Please include:

- the version or commit you were running (`ctf-agents-check` prints the
  environment, or use `git rev-parse HEAD`);
- the affected component — specialist, tool, sandbox backend, or the reporting
  server;
- a minimal reproduction: a challenge fixture, the exact command, and the
  relevant `.env` settings, with real credentials removed;
- what boundary you believe was crossed, referring to
  [docs/security_model.md](docs/security_model.md) where it helps.

You should get an acknowledgement within about a week. Please give us a
reasonable window to ship a fix before disclosing publicly; we will credit you
in the advisory unless you would rather stay anonymous.

## What counts as a vulnerability

The threat model is in [docs/security_model.md](docs/security_model.md). A
report is in scope when it breaks one of the boundaries stated there. Concretely:

- **Sandbox escape.** Model-generated Python or an emulated challenge binary
  reaching the host filesystem, the network, or a process outside its container.
- **Allowlist bypass.** Any path that reaches a host, port, or URL not permitted
  by `CTF_AGENTS_ALLOWED_NETWORKS`, including one authorized by challenge data
  rather than by the operator.
- **Opt-in bypass.** A dangerous capability activating without its documented
  flag — host Python execution without
  `CTF_AGENTS_ALLOW_HOST_PYTHON_EXECUTION=1`, Docker or foreign-ELF execution
  without `CTF_AGENTS_ALLOW_DOCKER=1`, and so on.
- **Artifact path escape.** Reading or writing outside the explicitly supplied
  artifact set.
- **Prompt injection that escalates.** Challenge-authored text that widens the
  operation allowlist, reaches a new host, defeats the evidence validator, or
  marks a run solved without a flag appearing in executed output. See
  [Untrusted content and prompt injection](docs/security_model.md#untrusted-content-and-prompt-injection).
- **Credential or flag leakage.** Secrets surviving redaction into logs,
  reports, the knowledge store, the campaign ledger, or an outbound live-reporting
  event.
- **Reporting server issues.** Write access without the ingestion token,
  cross-origin reads from an unconfigured origin, or token disclosure to the
  static frontend.

## What does not count

These are the product doing its job, or your configuration choosing risk:

- The system executing an untrusted challenge binary inside its container. That
  is the feature. An escape from that container is a vulnerability; the execution
  itself is not.
- Anything you enabled through a documented dangerous opt-in. Setting
  `CTF_AGENTS_ALLOW_HOST_PYTHON_EXECUTION=1` runs arbitrary model-authored code
  on your machine, exactly as the flag's documentation says.
- The agent attacking a target you supplied. Authorization for a target is
  yours to hold; see [Authorized use](#authorized-use).
- Missing optional solver backends degrading capability. That is a functional
  gap — `ctf-agents-check` reports it — not a security boundary.
- Model output quality: wrong routing, a bad hypothesis, or a wasted turn.
- Findings against a challenge author's infrastructure rather than against this
  codebase. Report those to the challenge platform.

## Authorized use

This tool is for CTF challenges, platforms you have an account on, and systems
you are explicitly authorized to test. The network allowlist and the
opt-in flags bound what the software will do; they do not grant you permission
to do it. Confirming scope is the operator's responsibility.

## Supported versions

Fixes land on `main` and ship in the next tagged release. Only the most recent
release is supported; there are no long-term maintenance branches.

| Version  | Supported |
| -------- | --------- |
| 2.6.x    | Yes       |
| < 2.6    | No        |

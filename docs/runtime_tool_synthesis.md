# Runtime Tool Synthesis

Runtime tool synthesis is the coordinator's final recovery tier for challenges
that do not match a shipped playbook. It runs only after normal specialist
routing and the existing recovery review fail to solve the challenge.

## Flow

1. The coordinator passes a redacted challenge, recent results, and recent
   execution trace to the reasoner.
2. The reasoner proposes one JSON tool specification and quotes the evidence
   that motivated it.
3. The validator checks that the quoted evidence is present in the trace and
   that every operation stays within policy.
4. Existing wrappers execute the specification one operation at a time.
5. Only a flag extracted from executed output can produce `solved`.
6. The specification disappears after the run. Its non-sensitive technique
   name may be retained in solve-trace memory.

Supported operations are same-origin GET/POST requests, reads within supplied
challenge artifacts, bounded regular-expression extraction, base64/hex/URL
decoding, and JSON traversal. Variables flow only from earlier operations.

## Why it is declarative

The framework does not allow a model to write arbitrary Python modules, shell
scripts, package installers, or permanent plugins during a solve. Those forms
of synthesis would bypass the repository's network, subprocess, filesystem,
and review boundaries. The operation DSL still lets a model construct a novel
tool wrapper while keeping execution inside known, testable primitives.

## Current limits

- One proposal is attempted per stalled solve.
- Specifications contain at most 12 operations and 50 KB of JSON.
- HTTP stays on the challenge origin and does not follow redirects.
- Artifact reads are capped and cannot escape supplied paths.
- Regexes reject lookarounds, backreferences, and quantified groups.
- Authentication headers and raw cookies cannot be synthesized.
- No environment mutation or dependency installation is supported.

Broader environment playbooks should be added as reviewed declarative
operations backed by isolated wrappers—not by relaxing arbitrary host-code
execution.

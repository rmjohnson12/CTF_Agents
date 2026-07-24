# Runtime Tool Synthesis

Runtime tool synthesis is the coordinator's final, AI-driven recovery tier for
challenges that do not match a shipped playbook. It runs after normal
specialist routing and recovery review fail, then gives the configured model a
bounded observe/propose/execute loop instead of requiring a prewritten solver.

## Flow

1. The coordinator passes a redacted challenge, recent results, and recent
   execution trace to the reasoner.
2. The reasoner proposes one JSON tool specification and quotes the evidence
   that motivated it.
3. The validator checks that the quoted evidence is present in the trace and
   that every operation stays within policy.
4. Existing wrappers execute the specification one operation at a time.
5. Bounded, redacted observations are returned to the model for the next turn.
6. The model may revise its hypothesis or correct a rejected action, up to four
   turns by default.
7. Only a flag extracted from executed output can produce `solved`.
8. Specifications disappear after the run. Non-sensitive technique
   name may be retained in solve-trace memory.

Supported operations are same-origin GET/POST requests, reads within supplied
challenge artifacts, read-only Radare2 disassembly of supplied binaries,
bounded regular-expression extraction, base64/hex/URL decoding, and JSON
traversal. Variables flow from earlier operations and remain available across
turns in the same ephemeral solve, allowing later actions to extract or decode
newly observed evidence.

## Why it is declarative

The framework does not allow a model to write arbitrary Python modules, shell
scripts, package installers, or permanent plugins during a solve. Those forms
of synthesis would bypass the repository's network, subprocess, filesystem,
and review boundaries. The operation DSL still lets a model construct a novel
tool wrapper while keeping execution inside known, testable primitives.

## Current limits

- Four model/tool turns are attempted per stalled solve (hard cap: eight).
- Specifications contain at most 12 operations and 50 KB of JSON.
- Individual observations are capped before they are returned to the model and
  are not persisted in the public solve result.
- HTTP stays on the challenge origin and does not follow redirects.
- Artifact reads are capped and cannot escape supplied paths.
- Regexes reject lookarounds, backreferences, and quantified groups.
- Authentication headers and raw cookies cannot be synthesized.
- No environment mutation or dependency installation is supported.

Broader environment playbooks should be added as reviewed declarative
operations backed by isolated wrappers—not by relaxing arbitrary host-code
execution.

# Adding a Playbook

A playbook belongs in an existing specialist when it combines known evidence
with a bounded solution strategy.

1. Define the minimum evidence required to activate it.
2. Reject weak or generic matches early.
3. Put it before expensive generic recovery only when confidence is high.
4. Bound attempts, payload size, time, and target paths.
5. Return immediately after a verified flag.
6. Store only sanitized metadata in artifacts.
7. Add a positive regression test and at least one false-positive test.
8. Prefer a general vulnerability pattern over a challenge-name special case.

Document the higher-level capability, not every payload variant, in
`capabilities.md`.

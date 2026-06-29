# Contributing

1. Create a focused branch.
2. Reproduce the behavior or define the maintenance objective.
3. Make the smallest compatible change.
4. Add or update deterministic tests.
5. Run the focused tests and the full suite.
6. Update the relevant document under `docs/`.
7. Describe behavior, risk, and validation in the pull request.

Changes should not weaken target allowlisting, environment isolation, artifact
redaction, Docker cleanup, SSH restrictions, or generated-code controls.

New abstractions should remove duplication or clarify an interface. Avoid
creating a framework layer for a single call site.

Bug reports should include the challenge category, entrypoint, sanitized plan
output, final status, relevant steps, and a minimal reproducible fixture where
possible.

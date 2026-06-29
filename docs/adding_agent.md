# Adding an Agent

Add a specialist only when an existing category cannot own the capability.

1. Subclass `BaseAgent` under `agents/specialists/<category>/`.
2. Define stable capabilities and an evidence-based `analyze_challenge()`.
3. Implement `solve_challenge()` with serializable status, steps, artifacts,
   and optional flag fields.
4. Register the agent in both CLI coordinator builders.
5. Add classifier and routing tests.
6. Add a deterministic example and focused solve test.
7. Document the category in `capabilities.md`.

Agents should coordinate bounded tools; they should not duplicate HTTP,
subprocess, filesystem-safety, or redaction policy.

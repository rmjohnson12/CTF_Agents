# Golden-Path Examples

Each category directory contains a deterministic `challenge.json` contract.
The contract documents the expected command, routing category, selected agent,
terminal status, and flag. `tests/e2e/test_golden_examples.py` validates every
contract without network access or an LLM.

These small contracts are the stable routing and documentation layer. Deeper
solver behavior is covered by the corresponding specialist unit fixtures and
the evaluation suite under `challenges/evaluation/`.

Some categories also contain nested workflow fixtures. For example,
`examples/hardware/forth/` records a deterministic diagnostic session and is
validated without opening a network connection.

Run the golden paths with:

```bash
pytest -q -p no:cacheprovider tests/e2e/test_golden_examples.py
```

To add an example:

1. Create `examples/<category>/challenge.json`.
2. Use a stable `golden_<category>` ID.
3. Provide `expected.command`, `expected.category`, `expected.agent`,
   `expected.status`, and `expected.flag`.
4. Keep the fixture local, deterministic, and free of credentials.
5. Add specialist-level solve coverage when the fixture exercises more than
   parsing and routing.

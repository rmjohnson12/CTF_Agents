# Quantum Agent

The quantum specialist handles challenges whose evidence describes qubits,
quantum circuits, entanglement, Bell/EPR pairs, BB84, or a basis-dependent
commitment protocol. It is registered as `quantum_agent` and can be selected by
either an explicit `quantum` category or strong content evidence.

## Deterministic Oathbinding Path

The implemented solver targets an Oathbinding-style HTTP API that exposes
`/api/oath`, `/api/new`, `/api/commit`, `/api/peek`, and `/api/open`. It first
verifies that the advertised contract supports `H` and `CX`; it does not treat
an arbitrary quantum-themed endpoint as compatible.

For each round, the agent prepares repeated Bell-pair slots:

```text
H(a)
CX(a, b)
```

The two halves of `|Phi+>` have correlated measurement outcomes in both the Z
and X bases. After the verifier reveals its basis, the agent measures the
retained `a` halves in that basis and opens the sealed `b` halves with the same
values. This is deterministic protocol exploitation and does not require an
LLM or a local quantum-computing package.

## Safety and Validation

- The target must pass `CTF_AGENTS_ALLOWED_NETWORKS` policy.
- Requests use a 10-second timeout and require object-shaped JSON responses.
- The commitment challenge must be a bit and peek results must contain exactly
  the advertised number of binary outcomes.
- Work is capped at 128 rounds and 128 strands.
- A run is solved only when the final validated response contains a flag.

## Input

```json
{
  "id": "quantum-oath",
  "category": "quantum",
  "description": "Exploit the basis-dependent bit commitment protocol.",
  "url": "http://TARGET:PORT"
}
```

Validate the deterministic routing contract offline with:

```bash
LLM_PROVIDER=none python3 -m pytest -q tests/e2e/test_golden_examples.py
```

The protocol interaction itself is covered by
`tests/unit/test_quantum_agent.py`; the golden routing contract is validated by
`tests/e2e/test_golden_examples.py` without network access.

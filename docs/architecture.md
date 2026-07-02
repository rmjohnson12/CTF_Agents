# Architecture

CTF_Agents separates challenge interpretation, routing, execution, persistence,
and reporting so each can evolve without rewriting the coordinator.

```text
instruction / challenge JSON
            |
      challenge parser
            |
   classifier + reasoner
            |
 strategy selector / coordinator
       |          |
 specialist    support agent
       |          |
       bounded tool wrappers
            |
 result manager, checkpoints, knowledge, campaign ledger
```

## Major systems

- **Routing**: classifier, LLM reasoner, strategy selector, performance history,
  and solve-trace hints choose the next bounded action.
- **Execution**: agents call typed wrappers rather than constructing arbitrary
  shell commands or network requests.
- **Agent registration**: decorated specialist and support classes are
  discovered by `AgentRegistry`, constructed in stable order, and injected
  with only the CLI dependencies their constructors explicitly accept.
- **Artifacts**: local files, fetched content, and generated outputs are passed
  through challenge and result dictionaries with sensitive fields redacted.
- **Learning**: successful routing signatures and artifact keys are stored
  without retaining raw flags.
- **Reporting**: checkpoints and final JSON reports preserve decisions, steps,
  and bounded artifacts for debugging and resume.
- **Campaigns**: providers feed local challenge definitions to a retry-bounded
  runner backed by a SQLite attempt ledger.

The coordinator remains iterative: deterministic evidence-led fast paths handle
high-confidence cases, while the LLM is reserved for ambiguous planning and
evidence-bound recovery.

For the older component-level walkthrough, see
[architecture/system_overview.md](architecture/system_overview.md).

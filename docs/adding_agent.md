# Adding an Agent

Add a specialist only when an existing category cannot own the capability.

1. Subclass `BaseAgent` under `agents/specialists/<category>/`.
2. Decorate the class with `@AgentRegistry.register(order=...)`.
3. Define stable capabilities and an evidence-based `analyze_challenge()`.
4. Implement `solve_challenge()` with serializable status, steps, artifacts,
   and optional flag fields.
5. Add classifier and routing tests.
6. Add a deterministic example and focused solve test.
7. Document the category in `capabilities.md`.

```python
from agents.base_agent import AgentType, BaseAgent
from agents.registry import AgentRegistry


@AgentRegistry.register(order=150)
class ExampleAgent(BaseAgent):
    def __init__(self, reasoner=None):
        super().__init__("example_agent", AgentType.SPECIALIST)
        self.reasoner = reasoner
```

The registry discovers decorated classes automatically. CLI builders provide a
dependency map; constructor parameters such as `reasoner`, `browser_tool`,
`john_tool`, and `hashcat_tool` receive matching values when available. New
specialists therefore do not require edits to `ask.py` or `main.py`. Choose a
stable order value and add the expected agent ID to the registry regression
test.

Agents should coordinate bounded tools; they should not duplicate HTTP,
subprocess, filesystem-safety, or redaction policy.

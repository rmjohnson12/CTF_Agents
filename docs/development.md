# Development

## Local workflow

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q -p no:cacheprovider
ruff check .
mypy
ctf-agents-check
```

`[dev]` pulls in every specialist extra plus the test and lint tooling. See the
extras table in the [README](../README.md#installation) for leaner installs.
Dependencies and the ruff/mypy/pytest configuration all live in
`pyproject.toml`; `uv.lock` pins the resolved versions.

Keep changes narrow, preserve existing interfaces, and prefer extending an
existing agent or wrapper over adding a parallel abstraction.

## Conventions

- Use type hints on public and non-trivial internal interfaces.
- Return serializable dictionaries from agent solve methods.
- Put external execution behind `tools/` wrappers.
- Record concise evidence and failure reasons in `steps`.
- Do not persist credentials, raw session state, or raw flags.
- Add a focused regression test for every bug fix.
- Update modular documentation when behavior changes.

## Extension guides

- [adding_agent.md](adding_agent.md)
- [adding_tool.md](adding_tool.md)
- [adding_playbook.md](adding_playbook.md)
- [testing.md](testing.md)
- [release_process.md](release_process.md)

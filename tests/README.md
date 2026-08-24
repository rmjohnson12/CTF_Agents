# Test Directory

This directory contains tests for the CTF multi-agent system.

## Structure

### unit/
Unit tests for individual components:
- Agent class tests
- Tool wrapper tests
- Core system component tests
- Utility function tests
- Configuration loader tests

### integration/
Integration tests for multi-component interactions:
- Agent communication tests
- End-to-end challenge solving tests
- Knowledge base integration tests
- Tool chain tests
- System workflow tests

### e2e/fixtures/
Checked-in fixture files used by end-to-end tests:
- Small reverse-engineering scripts
- Log-analysis samples
- Binary/string artifacts
- Tiny local wordlists for deterministic cracking tests

## Testing Guidelines

### Unit Tests
- Test individual functions and classes in isolation
- Use mocks for external dependencies
- Fast execution (< 1 second per test)
- High code coverage (>80%)

### Integration Tests
- Test real interactions between components
- Use test databases and services
- May take longer to execute
- Focus on critical paths

### Test Naming Convention
```python
# Format: test_<functionality>_<scenario>_<expected_result>
def test_coordinator_assign_task_web_challenge_assigns_web_agent():
    pass

def test_crypto_agent_solve_caesar_cipher_returns_correct_flag():
    pass
```

## Running Tests

```bash
# Daily developer sanity check
python3 check_setup.py

# CLI discovery should print argparse help, not start a solve
python3 ask.py --help

# Run all tests
pytest

# Run the low-noise daily review subset
pytest -q -p no:cacheprovider tests/unit/test_iterative_coordinator.py tests/unit/test_llm_reasoner_fixes.py tests/unit/test_reverse_agent.py

# Run unit tests only
pytest tests/unit/

# Run end-to-end smoke prompts
pytest tests/e2e/test_smoke_prompts.py

# Run opt-in live LLM provider smoke tests
CTF_AGENTS_RUN_LIVE_LLM_TESTS=1 pytest tests/integration/test_live_llm_provider.py

# Run with coverage
pytest --cov=agents --cov=core --cov=tools

# Run a specific existing test file
pytest tests/unit/test_reasoner_routing.py

# Run with verbose output
pytest -v
```

## Test Requirements

Test dependencies are installed from the repository's main `requirements.txt`.
At minimum, the checked-in test suite expects `pytest` and any runtime packages
used by the agents under test.

Live LLM tests are skipped unless `CTF_AGENTS_RUN_LIVE_LLM_TESTS=1` is set and
the root `.env` or shell environment contains a supported provider key.

## Continuous Integration

Tests should be:
- Run automatically on every commit
- Required to pass before merging
- Monitored for performance regression
- Generate coverage reports

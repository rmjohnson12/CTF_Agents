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

### mocks/
Mock objects and test fixtures:
- Mock challenges
- Mock agent responses
- Mock tool outputs
- Test data generators
- Stub implementations

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
# Run all tests
pytest

# Run unit tests only
pytest tests/unit/

# Run integration tests
pytest tests/integration/

# Run with coverage
pytest --cov=agents --cov=core --cov=tools

# Run specific test file
pytest tests/unit/test_coordinator.py

# Run with verbose output
pytest -v
```

## Test Requirements

Create a `requirements-test.txt` file with:
- pytest
- pytest-cov
- pytest-mock
- pytest-asyncio (if using async agents)
- hypothesis (for property-based testing)

## Continuous Integration

Tests should be:
- Run automatically on every commit
- Required to pass before merging
- Monitored for performance regression
- Generate coverage reports

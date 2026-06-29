# Testing

Run a focused test while iterating, then the full suite:

```bash
pytest -q -p no:cacheprovider tests/unit/test_web_tools.py
pytest -q -p no:cacheprovider
```

## Required coverage

- routing evidence and selected target
- coordinator iteration, fallback, duplicate suppression, and resume
- wrapper success, malformed output, missing tools, failure, and timeout
- artifact parsing, corruption, and unsupported formats
- campaign retry bounds and exports
- network allowlists and URL validation
- environment isolation and generated-code controls
- redaction, Docker cleanup, and SSH restrictions

Tests must not require public internet access or live CTF instances. Use local
fixtures and injected fake wrappers. Live validation can supplement but never
replace deterministic regression tests.

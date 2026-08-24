# Release Process

1. Confirm the working tree and intended scope.
2. Bump `__version__` in `core/_version.py`. That is the only place a version
   is declared; packaging and the tag both read from it.
3. Run `pytest -q -p no:cacheprovider`, `ruff check .`, and `mypy`.
4. Refresh `uv.lock` (`uv lock`) and commit it if dependencies moved.
5. Build and check the artifacts: `python -m build && twine check dist/*`.
6. Run `ctf-agents-check` and CLI help-path checks.
7. Validate documentation links and golden-path examples.
8. Review security-boundary changes explicitly.
9. Review benchmark deltas for solve rate, runtime, iterations, and failures.
10. Update release notes or the pull-request summary.
11. Tag only from a reviewed, green default branch. Tags are `vMAJOR.MINOR.PATCH`
    and must match `core/_version.py`.

Do not release with unexplained test skips, embedded runtime state, credentials,
or tracked challenge output artifacts.

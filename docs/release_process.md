# Release Process

1. Confirm the working tree and intended scope.
2. Run `pytest -q -p no:cacheprovider`.
3. Run `python3 check_setup.py` and CLI help-path checks.
4. Validate documentation links and golden-path examples.
5. Review security-boundary changes explicitly.
6. Review benchmark deltas for solve rate, runtime, iterations, and failures.
7. Update release notes or the pull-request summary.
8. Tag only from a reviewed, green default branch.

Do not release with unexplained test skips, embedded runtime state, credentials,
or tracked challenge output artifacts.

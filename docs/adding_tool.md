# Adding a Tool

1. Place the wrapper under the relevant `tools/` package.
2. Accept typed inputs and return a small serializable result object.
3. Use argument arrays rather than shell command strings.
4. Enforce URL, host, filesystem, timeout, and environment policy before work.
5. Capture bounded stdout, stderr, status, duration, and timeout state.
6. Add tests for success, missing binaries, non-zero exits, malformed output,
   timeout, and policy rejection.
7. Inject the wrapper into agents so tests can use fakes.

Do not make a tool responsible for challenge routing or flag-report policy.

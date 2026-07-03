# Hack The Box integration

Automates the documented Hack The Box **challenge** workflow for **your own
authenticated account**: discover challenges, download files, optionally spawn
instances, run the existing CTF_Agents solver against the provided artifacts /
target, and write a report of candidate flags.

> **Scope & safety.** This tool operates only on challenges your account can
> access. It never targets non-HTB hosts, never brute-forces login, never
> bypasses subscriptions or access controls, and never submits a flag unless you
> explicitly pass `--submit`. Respect HTB's rate limits, cooldowns, and rules.

## Package layout

```
integrations/hackthebox/
  config.py            # endpoint table (with confidence notes) + tunables
  errors.py            # typed exceptions
  models.py            # Challenge / SpawnInfo / ChallengeAttempt / RunReport
  auth.py              # token / cached-session / login (2FA-aware) auth
  client.py            # defensive v4 API client
  archive.py           # zip-slip-safe extraction
  challenge_runner.py  # orchestration (discover -> spawn -> download -> solve)
  reporting.py         # Markdown + JSON reports
  browser.py           # optional Playwright fallback (opt-in, UI-only stubs)
  cli.py               # command-line entry point
```

> The repo uses a flat top-level layout, so the CLI is invoked as
> `python -m integrations.hackthebox.cli` (the spec's `ctf_agents.` prefix maps
> to this package).

## Setup

1. Generate an **App Token** in your HTB profile settings (recommended auth).
2. Provide credentials via environment variables (never commit them):

   | Variable       | Purpose                                             |
   |----------------|-----------------------------------------------------|
   | `HTB_TOKEN`    | App Token (preferred). Bypasses interactive 2FA.    |
   | `HTB_EMAIL`    | Email for password login (fallback).                |
   | `HTB_PASSWORD` | Password for password login (fallback).             |
   | `HTB_OTP`      | One-time 2FA code (only used if provided).          |

   ```bash
   export HTB_TOKEN="your-app-token"
   # or, fallback:
   export HTB_EMAIL="you@example.com"
   export HTB_PASSWORD="..."
   ```

3. Sessions are cached in a git-ignored `.htb_session.json` (owner-only perms).
   Only a token + your profile are cached — never your password.

### Optional environment overrides

- `HTB_API_BASE` — API base URL (default `https://labs.hackthebox.com/api/v4`).
- `HTB_EP_*` — override any single endpoint path if the API changes (see the
  table in `config.py`, e.g. `HTB_EP_CHALLENGE_LIST`).
- `HTB_TIMEOUT_SECONDS`, `HTB_SPAWN_TIMEOUT_SECONDS`, `HTB_ARCHIVE_PASSWORD`,
  `HTB_MAX_EXTRACT_BYTES`.

## Dry-run mode (default)

Dry-run is the **default** and performs **no** live download/spawn/submit — it
only lists challenges (read-only) and prints the plan:

```bash
python -m integrations.hackthebox.cli --category web --max 3 --dry-run
```

## Real run mode

A live run requires the explicit `--execute` flag and writes a report:

```bash
python -m integrations.hackthebox.cli --category web --max 3 --execute \
    --output reports/htb_results.md
```

This will, per selected challenge: create `runs/htb/<slug>/`, spawn an instance
if the challenge needs one (unless `--no-start`), download and safely extract
files, run the solver within HTB-provided scope, and record candidate flags.

## Selecting challenges

- `--category web|crypto|pwn|reversing|...`
- `--difficulty Easy|Medium|Hard|...`
- `--max N`
- `--include-retired`, `--include-solved`, `--include-locked` — retired, solved,
  and locked/unavailable challenges are **excluded by default**.

## Reports

Two files are written per run (default directory `reports/`, which is
git-ignored):

- `reports/htb_results_<timestamp>.md` — human-readable Markdown.
- `reports/htb_results_<timestamp>.json` — machine-readable sidecar.

Each report includes the run timestamp, your user id/name, the selected filters,
and per challenge: metadata, whether it was spawned, target info, downloaded
files, solver steps, candidate flags, submission result (if `--submit`), errors,
and runtime duration.

## Flag submission (opt-in)

Flags are **never** submitted automatically. Candidate flags are written to the
report by default. To submit, pass both `--execute` and `--submit`; only flags
matching the `HTB{...}` format are ever submitted:

```bash
python -m integrations.hackthebox.cli --category web --max 1 --execute --submit
```

## Browser fallback

The API is the primary interface. A Playwright fallback exists for UI-only
actions but is **opt-in** (`--browser-fallback`) and currently ships as verified
stubs — it never automates login. Install Playwright to use it:

```bash
pip install playwright && python -m playwright install chromium
```

## Avoiding committed secrets

`.gitignore` already excludes `.htb_session.json`, `*.ovpn`, `runs/`, and
`reports/`. Keep credentials in environment variables or a git-ignored
`.htb.env`. Tokens and cookies are redacted in logs and never written to
reports.

## Error handling

The run is resilient: expired sessions, 401/403, changed endpoints (404),
cooldowns/rate limits (429, with bounded backoff), unavailable instances, failed
downloads, extraction errors, and solver timeouts are all handled per challenge —
one failure never aborts the whole run. Auth failures are the only fatal case.

## Endpoint confidence & limitations

The v4 API docs are community-maintained, so endpoints are treated as unverified
until they succeed at runtime. `config.py` annotates each endpoint's confidence:

- **High:** `user/info`; instance `start`/`stop` — confirmed against the live
  HTB app frontend as `POST /container/start` and `POST /container/stop` with
  body `{"containerable_id": <challenge id>}` (the community-documented
  `/challenge/start` no longer exists and returns 404). Spawning is asynchronous:
  the IP:PORT appears in the challenge's `play_info` a few seconds after start,
  which the client polls for.
- **Medium:** challenge list/info/download/categories/own.
- **Low (verify before trusting):** email/password `login` + 2FA.

If an endpoint has changed, the client raises a clear `HTBEndpointError` ("the
endpoint may have changed") instead of crashing. Fix it by setting the relevant
`HTB_EP_*` override or updating `config.py`. 2FA over the API is intentionally
**not** implemented against an unverified endpoint — use an App Token.

**Solving is not guaranteed even when the plumbing works.** The integration
handles auth, discovery, spawning, target authorization, download, and reporting.
Whether a given challenge is actually *solved* depends on the underlying
CTF_Agents specialist for that category. Some specialists are still tuned to
specific challenge templates and will not generalize to every challenge; in that
case the run completes cleanly with the spawned target, the solver's steps, and
no candidate flag, rather than a crash.

## Testing

Unit tests (no network) live in `tests/unit/hackthebox/`:

```bash
python -m pytest tests/unit/hackthebox/ -q
```

Opt-in integration tests hit the real API (read-only: auth + list only) and run
only when enabled with credentials present:

```bash
RUN_HTB_INTEGRATION_TESTS=1 HTB_TOKEN=... python -m pytest tests/unit/hackthebox/test_htb_integration.py -q
```

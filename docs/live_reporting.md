# Live Solve Reporting

The optional reporting layer records structured coordinator and agent progress
in `logs/reporting.db`. It exposes a small JSON API plus Server-Sent Events
(SSE), while leaving normal solves unchanged when reporting is not configured.

## Architecture

- `ProgressUpdate` validates the wire format.
- `ReportingStore` appends events to a dedicated SQLite database.
- `reporting_server.py` serves ingestion, timeline, and SSE routes.
- `HttpProgressReporter` sends coordinator and specialist lifecycle events when
  `CTF_AGENTS_REPORTING_URL` is set.
- Existing specialists can call `self.emit_progress(...)` to add finer-grained
  events during long-running work.

The Lovable site is a static frontend; it cannot run this Python service. Deploy
the reporting server separately behind HTTPS, then let the frontend consume its
read API. Never put the write token in browser JavaScript.

## Start the service

For local development:

```bash
export CTF_AGENTS_REPORTING_WRITE_TOKEN='replace-with-a-long-random-token'
export CTF_AGENTS_REPORTING_READ_TOKEN='replace-with-a-different-token'
export CTF_AGENTS_REPORTING_ALLOWED_ORIGINS='https://ctf-agents.lovable.app'
python3 reporting_server.py --host 127.0.0.1 --port 8787
```

For a non-loopback bind, a write token is required. In production, terminate
TLS at a reverse proxy or hosting platform and expose only HTTPS.

## Configure agents

Point any CLI/coordinator process at the deployed reporting service:

```bash
export CTF_AGENTS_REPORTING_URL='https://reports.example.com'
export CTF_AGENTS_REPORTING_WRITE_TOKEN='replace-with-a-long-random-token'
python3 ask.py "Solve the authorized challenge in ./challenge"
```

Reporting is best-effort: an unavailable reporting service logs a warning but
does not fail or alter the solve.

## API routes

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/api/v1/updates` | Validate and append one progress event |
| `GET` | `/api/v1/runs/{run_id}/timeline` | Return a run in chronological order |
| `GET` | `/api/v1/runs/{run_id}/stream` | Stream persisted and new events over SSE |
| `GET` | `/health` | Liveness check |

Send protected requests with `Authorization: Bearer TOKEN`. Timeline pagination
supports `after_id` and `limit`. SSE clients can reconnect with
`Last-Event-ID`; missed events are replayed from SQLite before live streaming.

## Submit an update

```bash
curl -X POST https://reports.example.com/api/v1/updates \
  -H 'Authorization: Bearer WRITE_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{
    "challenge_id": "forklift-forth",
    "run_id": "5d2c13b7-7eb0-4ce4-9994-a4c7b0da8148",
    "timestamp": "2026-07-01T16:30:00Z",
    "agent_name": "hardware_agent",
    "agent_type": "specialist",
    "status": "progress",
    "step_title": "Dictionary enumerated",
    "step_description": "Confirmed the Forth system word after the allowlist gate.",
    "confidence": 0.96,
    "elapsed_seconds": 7.4,
    "artifacts": {"dictionary_word": "system"},
    "final_flag": null,
    "error_message": null
  }'
```

The server generates `event_id` and `timestamp` when omitted.

## Retrieve a timeline

```bash
curl -H 'Authorization: Bearer READ_TOKEN' \
  'https://reports.example.com/api/v1/runs/RUN_ID/timeline'
```

Example response:

```json
{
  "run_id": "RUN_ID",
  "count": 2,
  "updates": [
    {
      "id": 1,
      "event_id": "f9248aa3-0a5d-4b45-b83a-cb9558a04d5f",
      "challenge_id": "forklift-forth",
      "run_id": "RUN_ID",
      "timestamp": "2026-07-01T16:30:00Z",
      "agent_name": "coordinator",
      "agent_type": "coordinator",
      "status": "running",
      "step_title": "Run started",
      "step_description": "Coordinator accepted the challenge and began analysis.",
      "confidence": null,
      "elapsed_seconds": 0.0,
      "artifacts": {},
      "final_flag": null,
      "error_message": null
    }
  ]
}
```

## Stream updates

```bash
curl -N -H 'Authorization: Bearer READ_TOKEN' \
  'https://reports.example.com/api/v1/runs/RUN_ID/stream'
```

Native browser `EventSource` cannot attach an authorization header. For private
timelines, proxy SSE through a server-side function or use authenticated
`fetch()` streaming. For a deliberately public, redacted dashboard, set
`CTF_AGENTS_REPORTING_PUBLIC_READ=1`; POST ingestion remains token-protected.

## Emit progress inside an agent

Every registered agent inherits a safe helper:

```python
self.emit_progress(
    status="progress",
    step_title="Leak validated",
    step_description="Resolved the bundled libc base from puts@GOT.",
    confidence=0.94,
    artifacts={"primitive": "indexed GOT leak"},
)
```

The coordinator already reports run start, initial routing, agent/tool start,
returned steps, agent/tool completion, and final status.

## Security defaults

- Flags embedded in descriptions and artifacts are redacted before transport.
- `final_flag` is redacted unless both the sender and server explicitly opt in
  with `CTF_AGENTS_REPORT_FINAL_FLAG=1` and
  `CTF_AGENTS_REPORTING_STORE_FLAGS=1`.
- Sensitive artifact keys such as tokens, credentials, and cookies are redacted.
- Browser origins are denied unless listed in
  `CTF_AGENTS_REPORTING_ALLOWED_ORIGINS`.
- The server refuses a non-loopback bind without a write token.
- Public reads are disabled by default.

The in-process SSE broker is intentionally simple and supports a single server
process. SQLite remains durable across restarts. A future multi-replica service
can replace only the broker with Redis/Postgres notifications without changing
the event schema or frontend API.

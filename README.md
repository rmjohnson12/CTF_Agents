# CTF_Agents

CTF_Agents is a multi-agent framework for authorized Capture The Flag work.
It classifies a challenge, selects a specialist, executes bounded tools and
playbooks, records evidence, and reports either a verified result or a concrete
failure reason.

The project supports cryptography, quantum protocols, reverse engineering, web,
pwn, hardware, forensics, blockchain, secure-coding, networking, OSINT,
log-analysis, and general coding challenges. Platform labels do not have to map
one-to-one to specialists: an AI/ML challenge built around a poisoned Git
archive, for example, can route to forensics and then use AI-driven recovery.
Detailed coverage lives in
[docs/capabilities.md](docs/capabilities.md).

## Installation

```bash
git clone https://github.com/rmjohnson12/CTF_Agents.git
cd CTF_Agents
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python3 check_setup.py
```

The project-root `.env.example` is the supported configuration template. Add
one or more optional provider credentials for live model reasoning.
Deterministic specialist paths remain available without an LLM where
implemented.

## Quick Start

Use the natural-language CLI:

```bash
python3 ask.py "Crypto challenge: decode 48 54 42 7b 68 65 78 7d"
python3 ask.py --plan "Web challenge at http://127.0.0.1:3000"
```

Remote targets must be explicitly allowlisted:

```bash
CTF_AGENTS_ALLOWED_NETWORKS=TARGET \
  python3 ask.py "Solve the authorized web challenge at http://TARGET:PORT"
```

Structured challenge JSON can use the lower-level entrypoint:

```bash
python3 main.py challenges/templates/example_crypto_hex.json
```

Run a bounded local campaign:

```bash
python3 campaign.py challenges/active --limit 3
python3 campaign.py challenges/benchmarks/manifest.json --json-out results/benchmark.json
```

## Basic Examples

```bash
# Local source or artifact folder
python3 ask.py "Analyze this web challenge in ~/Downloads/challenge"

# Hardware capture
python3 ask.py "Decode the Saleae capture in ~/Downloads/capture.sal"

# Remote pwn target with local files
CTF_AGENTS_ALLOWED_NETWORKS=TARGET \
  python3 ask.py "Pwn challenge at TARGET:PORT; files are in ~/Downloads/pwn"

# Git repository with evidence in deleted history
python3 ask.py "Forensics challenge; files are in ~/Downloads/repository"
```

See [examples/README.md](examples/README.md) for deterministic golden paths.

## Optional AI-Driven Recovery

CTF_Agents can use an actual configured model, rather than only hard-coded
playbooks. The coordinator tries normal specialist routes first. If they stall,
the model receives bounded, redacted observations and can iteratively propose
evidence-backed operations. The default recovery budget is four model/tool
turns.

Supported providers are NVIDIA NIM, Anthropic, OpenAI, Google Gemini/Vertex AI,
and local Ollama. Choose a preferred provider and configure its credential in
the project-root `.env`:

```dotenv
LLM_PROVIDER=nvidia
NVAPI_KEY=your_nvidia_api_key

# Recommended when the model needs to calculate, simulate, or parse raw data.
CTF_AGENTS_SANDBOX=docker
```

The recovery loop can compose same-origin HTTP requests, bounded artifact reads,
regular-expression extraction, base64/hex/URL decoding, JSON traversal,
read-only Radare2 disassembly, and read-only Git history/patch inspection.
Values remain available between recovery turns.

For algorithmic work, the model can author a temporary Python computation. It
does not run in the coordinator process: execution is disabled by default and
is permitted only through the locked-down Docker backend or the explicit,
dangerous host-execution opt-in documented in `.env.example`. Docker compute
runs without network access and with read-only artifact mounts, resource
limits, and a strict timeout.

Only a flag found in executed output can mark a run as solved. Model suggestions
and guesses are not accepted as results. Live reasoning is best-effort:
provider availability, quota, output quality, and the turn limit can still
produce an `attempted` result with a concrete trace instead of a flag.

See [Runtime tool synthesis](docs/runtime_tool_synthesis.md) and
[Security model](docs/security_model.md) for the complete operation and policy
boundaries.

## Optional Live Reporting

Agents can send validated progress events to a configurable HTTP endpoint for
durable timelines and SSE dashboards. Start the local service with
`python3 reporting_server.py`, then set `CTF_AGENTS_REPORTING_URL` and a write
token before running a challenge. Reporting is opt-in and never changes a solve
outcome.
See [Live solve reporting](docs/live_reporting.md) for routes, payloads,
security defaults, and frontend integration guidance.

## Hack The Box integration

Automate the Hack The Box challenge workflow for **your own authenticated
account**: discover challenges, spawn instances, download files, run the solver,
and report candidate flags. It never submits a flag unless you explicitly opt in.

```bash
# 1. Put an App Token (https://app.hackthebox.com/profile/settings) in a
#    git-ignored file. HTB_EMAIL/HTB_PASSWORD also work; tokens are preferred.
echo 'HTB_TOKEN=your-app-token' > .htb.env

# 2. Dry-run (default; read-only listing, no downloads/spawns/submits):
python3 -m integrations.hackthebox.cli --name "The Suspicious Domain" --dry-run
python3 -m integrations.hackthebox.cli --category web --max 3 --dry-run

# 3. Real run (requires --execute): spawns instances, downloads/extracts files,
#    runs the solver, writes reports/htb_results_<ts>.md and a .json sidecar.
python3 -m integrations.hackthebox.cli --category web --max 3 --execute \
    --output reports/htb_results.md

# 4. Submission is never automatic — it also requires --submit AND --execute.
```

Candidate flags are written to the report; the run authorizes only the exact
HTB-provided instance target for the solver and stops instances it started.
Full setup, filters, endpoint-confidence notes, and limitations are in
[docs/hackthebox_integration.md](docs/hackthebox_integration.md).

Editor-backed secure-coding targets are discovered through their exposed
directory and file APIs. The agent reviews a bounded set of source files,
applies evidence-backed vulnerability-class patches, confirms saved content by
read-back, restarts the service, and accepts a solve only when the target's
verification endpoint returns a flag. Current generic remediations include
unsafe recursive merges vulnerable to prototype pollution and delimiter
injection in flat-file user records.

API-driven web challenges are solved by discovering endpoints from the page and
its JavaScript, enumerating any option/command lists, and submitting candidate
values (secret/hidden options first) to action endpoints until a flag is
returned — no specific command or endpoint is hard-coded. Interactive coding
instances are handled from the spawned page rather than the short platform
description: the coding agent detects the page's grader endpoint, extracts the
problem statement, uses deterministic programs for recognized classes such as
weighted shortest-path problems, and otherwise can iterate with LLM-generated
code plus grader feedback.

Blockchain challenges are solved from their published contract source: the
agent identifies the win condition, compiles and deploys a bespoke attacker
contract when the exploit requires a contract caller (e.g. a `tx.origin` gate),
or executes source-detected transaction sequences such as pre-0.8 ERC20
underflow purchases. It signs the required web3 transactions and verifies
`isSolved()` before retrieving the flag.

## Persistence and Learning

Normal runs and campaigns use separate SQLite stores under `logs/`:

- `knowledge.db` stores reusable challenge facts.
- `performance.db` stores routing and outcome telemetry.
- `solve_traces.db` stores compact successful technique traces without raw
  flags.
- `attempts.db` stores bounded campaign attempts and failure history.

Sensitive result fields are redacted. Campaign and solve-trace flag comparisons
use hashes instead of raw flag values. See the
[Operator's guide](docs/operators_guide.md) for retention and reuse details.

## Repository Layout

```text
agents/       Coordinator, specialist, and support agents
core/         Routing, security, persistence, campaign, and result services
tools/        Bounded wrappers for external tools and protocols
integrations/ Third-party platform integrations (e.g. Hack The Box)
challenges/   Challenge templates, evaluations, and benchmark manifests
examples/     Deterministic documented regression examples
tests/        Unit, integration, and end-to-end tests
docs/         Architecture, operations, security, and contributor guides
config/       Runtime and tool configuration
```

## Documentation

- [Getting started](docs/getting_started.md)
- [Architecture](docs/architecture.md)
- [Capabilities](docs/capabilities.md)
- [Security model](docs/security_model.md)
- [Runtime tool synthesis](docs/runtime_tool_synthesis.md)
- [Live solve reporting](docs/live_reporting.md)
- [Hack The Box integration](docs/hackthebox_integration.md)
- [Operator's guide](docs/operators_guide.md)
- [Development](docs/development.md)
- [Contributing](docs/contributing.md)
- [Adding an agent](docs/adding_agent.md)
- [Adding a tool](docs/adding_tool.md)
- [Adding a playbook](docs/adding_playbook.md)
- [Testing](docs/testing.md)
- [Release process](docs/release_process.md)

## Safety and Scope

Use CTF_Agents only against systems and challenge instances you are authorized
to test. Network allowlists, environment isolation, artifact redaction, Docker
controls, and host-execution controls are documented in
[docs/security_model.md](docs/security_model.md).

## Development and Verification

Run the complete deterministic suite without contacting an LLM provider:

```bash
LLM_PROVIDER=none .venv/bin/python -m pytest -q
```

Provider integration tests are opt-in. New runtime, sandbox, and specialist
changes should include focused tests plus the full offline suite before
publication. See [Testing](docs/testing.md) for the available test groups.

## Status

CTF_Agents is under active development. Compatibility is preserved where
practical. Deterministic paths are regression-tested; provider-driven recovery
is intentionally reported as best-effort and may stop with an evidence-backed
failure instead of a solved flag.

## License

See [LICENSE](LICENSE).

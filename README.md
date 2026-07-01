# CTF_Agents

CTF_Agents is a multi-agent framework for authorized Capture The Flag work.
It classifies a challenge, selects a specialist, executes bounded tools and
playbooks, records evidence, and reports either a verified result or a concrete
failure reason.

The project supports cryptography, reverse engineering, web, pwn, hardware,
forensics, blockchain, secure-coding, networking, OSINT, log-analysis, and
general coding challenges. Detailed coverage lives in
[docs/capabilities.md](docs/capabilities.md).

## Installation

```bash
git clone https://github.com/rmjohnson12/CTF_Agents.git
cd CTF_Agents
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 check_setup.py
```

Copy `.env.example` to `.env` and add an optional supported LLM key for
LLM-assisted planning. Deterministic specialist paths remain available without
an LLM where implemented.

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
```

See [examples/README.md](examples/README.md) for deterministic golden paths.

## Optional Live Reporting

Agents can send validated progress events to a configurable HTTP endpoint for
durable timelines and SSE dashboards. Start the local service with
`python3 reporting_server.py`, then set `CTF_AGENTS_REPORTING_URL` and a write
token before running a challenge. Reporting is opt-in and never changes a solve
outcome.
See [Live solve reporting](docs/live_reporting.md) for routes, payloads,
security defaults, and frontend integration guidance.

## Repository Layout

```text
agents/       Coordinator, specialist, and support agents
core/         Routing, security, persistence, campaign, and result services
tools/        Bounded wrappers for external tools and protocols
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
- [Live solve reporting](docs/live_reporting.md)
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

## Status

CTF_Agents is under active development. Compatibility is preserved where
practical, and new changes should include focused tests and documentation.

## License

See [LICENSE](LICENSE).

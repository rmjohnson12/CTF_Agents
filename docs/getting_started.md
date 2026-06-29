# Getting Started

## Requirements

- Python 3.10 or newer
- Packages from `requirements.txt`
- Optional external security tools reported by `python3 check_setup.py`
- Optional LLM credentials in the project-root `.env`

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python3 check_setup.py
```

The project-root `.env.example` is the configuration template. Do not commit
real credentials or copy them into challenge artifacts and reports.

## Choose an entrypoint

`ask.py` accepts natural-language instructions and paths:

```bash
python3 ask.py "Forensics challenge; files are in ~/Downloads/capture"
```

Use `--plan` to inspect classification and routing without executing tools:

```bash
python3 ask.py --plan "Hardware challenge; file is firmware.bin"
```

`main.py` accepts a challenge JSON file:

```bash
python3 main.py challenges/templates/example_crypto_hex.json
```

`campaign.py` runs bounded local queues and benchmark manifests:

```bash
python3 campaign.py challenges/benchmarks/manifest.json
```

## Remote targets

Challenge metadata does not authorize network access. Explicitly allow the
authorized host or CIDR for the command:

```bash
CTF_AGENTS_ALLOWED_NETWORKS=127.0.0.1 python3 ask.py "Web challenge at http://127.0.0.1:3000"
```

See [security_model.md](security_model.md) before enabling Docker, remote
React/RSC execution, sensitive artifact capture, or generated host Python.

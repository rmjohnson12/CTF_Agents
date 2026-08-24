# Getting Started Guide

## Introduction

Welcome to the CTF Multi-Agent System. This guide covers the current install,
configuration, and challenge-running flow. For a short quickstart see
[docs/getting_started.md](../getting_started.md); this is the longer walkthrough.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.10 or higher**: The system is written in Python
- **pip**: Python package manager
- **Docker** (optional): For running containerized tools
- **Git**: For cloning the repository

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/rmjohnson12/CTF_Agents.git
cd CTF_Agents
```

### 2. Create a Virtual Environment

It's recommended to use a virtual environment to isolate dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Install CTF Tools

The system relies on various CTF tools. You can install them using:

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    nmap sqlmap nikto john hashcat \
    binwalk foremost exiftool \
    radare2 gdb strings
```

There is no bundled tool installer script. Use your platform package manager
and then run `python3 check_setup.py` to see which optional tools are available
or missing.

### 5. Configure the System

Copy the root environment template and customize it:

```bash
cp .env.example .env
# Edit .env with your LLM provider settings
```

At least one supported LLM configuration is recommended:

```bash
NVAPI_KEY=your_nvidia_key_here
# or
NVAPI_KEYS=first_key,second_key
# or
ANTHROPIC_API_KEY=your_claude_key_here
# or
OPENAI_API_KEY=your_openai_key_here
```

`LLM_PROVIDER` selects the first provider. Other configured providers remain
available as automatic fallbacks when the preferred service times out or
returns quota, service, or authorization errors. Run results include a
secret-free `llm_summary` showing calls, successful calls, failovers, and the
provider/model that actually answered.

For local Ollama:

```bash
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434/v1
OLLAMA_MODEL=llama3.1
```

Run the setup check after editing `.env`:

```bash
python3 check_setup.py
```

You can also review configuration files as needed:

```text
config/system_config.yaml
config/agents_config.yaml
config/tools_config.yaml
```

## Basic Usage

### Interactive Natural-Language CLI

```bash
python3 ask.py
```

Then enter a challenge prompt when asked. You can include local files, folders,
URLs, IPs, ports, credentials for authorized lab targets, and challenge text.

You can also pass a single prompt directly:

```bash
python3 ask.py "Solve this web challenge at http://127.0.0.1:8080. The files are in ~/Downloads/challenge"
```

### JSON Challenge Mode

Create a challenge JSON file (see `challenges/templates/` for examples):

```bash
python3 main.py challenges/templates/example_crypto_base64.json
```

Preview the routing plan without invoking agents or tools:

```bash
python3 main.py challenges/templates/example_crypto_base64.json --plan
```

Resume from an existing checkpoint:

```bash
python3 main.py challenges/templates/example_crypto_base64.json --resume
```

A minimal challenge JSON looks like this:

```json
{
  "id": "example_crypto_base64",
  "name": "Base64 Warmup",
  "category": "crypto",
  "description": "Decode the provided message and recover the flag.",
  "files": []
}
```

### Results

The CLI prints the run status, recovered flag when found, and recent steps.
Generated reports and artifacts are written under `results/`. Checkpoints,
knowledge, and runtime databases are written under `logs/`.

## Directory Structure

Understanding the directory structure will help you navigate the system:

```
CTF_Agents/
├── agents/           # Agent implementations
├── core/             # Core system components (routing, campaign, reporting)
├── tools/            # Tool wrappers and utilities
├── integrations/     # Third-party platform integrations (Hack The Box)
├── config/           # Configuration files
├── challenges/       # Challenge management
├── shared/           # Shared resources
├── logs/             # System logs, checkpoints, and local DBs
├── results/          # Challenge results
├── tests/            # Test suite
└── docs/             # Documentation
```

See [PROJECT_STRUCTURE.md](../../PROJECT_STRUCTURE.md) for the full source map.

## Configuration

### System Configuration

Edit `config/system_config.yaml` to configure:
- Concurrent challenge limits
- Timeout values
- Logging settings
- Performance options

### Agent Configuration

Edit `config/agents_config.yaml` to:
- Enable/disable specific agents
- Set agent priorities
- Configure capabilities
- Set resource limits

### Tool Configuration

Edit `config/tools_config.yaml` to:
- Specify tool paths
- Set tool timeouts
- Configure API keys
- Enable/disable tools

## Example Workflow

Here's a typical workflow for solving a challenge:

1. **Check Setup**
   ```bash
   python3 check_setup.py
   ```

2. **Run a Natural-Language Challenge**
   ```bash
   python3 ask.py "Solve this reversing challenge. Files are in ~/Downloads/rev_challenge"
   ```

3. **Or Run a JSON Challenge**
   ```bash
   python3 main.py challenges/templates/example_crypto_base64.json --plan
   python3 main.py challenges/templates/example_crypto_base64.json
   ```

4. **Review Solution**
   - Read the CLI output for status, flag, and recent steps.
   - Check `results/` for generated reports and artifacts.
   - Check `logs/checkpoints/` if you need to resume a coordinator run.

## Common Issues

### Tools Not Found

If you get errors about missing tools:
```bash
# Check tool configuration
cat config/tools_config.yaml

# Verify tool installation
which sqlmap
which nmap
```

### Permission Denied

Some tools require elevated privileges:
```bash
# Prefer configuring only the external tool that needs privileges.
# Avoid running the whole coordinator with sudo unless you fully trust the target
# files and understand the risk.
```

### Import Errors

If you encounter import errors:
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

## Hack The Box automation (optional)

To automate challenges against your own authorized Hack The Box account:

```bash
echo 'HTB_TOKEN=your-app-token' > .htb.env          # git-ignored
python3 -m integrations.hackthebox.cli --name "Flag Command" --dry-run
```

See [Hack The Box integration](../hackthebox_integration.md) for the full flow
(dry-run, `--execute`, and opt-in `--submit`).

## Next Steps

- Read the [Architecture Overview](../architecture/system_overview.md)
- Review the [Capabilities](../capabilities.md) and [Security model](../security_model.md)
- Learn about [Adding an agent](../adding_agent.md) or [Adding a tool](../adding_tool.md)
- Explore the [example challenges](../../challenges/templates/)

## Getting Help

- Read the [Operator's guide](../operators_guide.md) and [Testing guide](../testing.md)
- Run `python3 check_setup.py` to diagnose environment/tooling issues
- Open an issue on GitHub

## Contributing

Contributions are welcome — see the [Contributing guide](../contributing.md).

---

Happy hacking! 🚀

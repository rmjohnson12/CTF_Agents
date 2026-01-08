# Getting Started Guide

## Introduction

Welcome to the CTF Multi-Agent System! This guide will help you get started with installing, configuring, and using the system to solve CTF challenges.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.8 or higher**: The system is written in Python
- **pip**: Python package manager
- **Docker** (optional): For running containerized tools
- **Git**: For cloning the repository

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/TonyZeroArch/CTF_Agents.git
cd CTF_Agents
```

### 2. Create a Virtual Environment

It's recommended to use a virtual environment to isolate dependencies:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
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

# Or use the provided setup script
./scripts/install_tools.sh
```

### 5. Configure the System

Copy the example configuration files and customize them:

```bash
cp config/.env.example config/.env
# Edit config/.env with your settings

# Review and modify configuration files as needed
# - config/system_config.yaml
# - config/agents_config.yaml
# - config/tools_config.yaml
```

## Basic Usage

### Starting the System

```bash
python main.py
```

This will:
- Initialize all agents
- Start the coordinator
- Begin listening for challenges

### Submitting a Challenge

You can submit a challenge in several ways:

#### 1. Using the CLI

```bash
python submit_challenge.py \
    --name "My Challenge" \
    --category web \
    --difficulty medium \
    --description "Find the hidden flag" \
    --url http://challenge.local:8080 \
    --points 200
```

#### 2. Using a JSON File

Create a challenge JSON file (see `challenges/templates/` for examples):

```bash
python submit_challenge.py --file my_challenge.json
```

#### 3. Programmatically

```python
from core.challenge import Challenge, ChallengeCategory, ChallengeDifficulty
from agents.coordinator.coordinator_agent import CoordinatorAgent

# Create a challenge
challenge = Challenge(
    id="web_001",
    name="SQL Injection Challenge",
    category=ChallengeCategory.WEB,
    difficulty=ChallengeDifficulty.MEDIUM,
    description="Find the flag in the database",
    points=200,
    url="http://challenge.local:8080"
)

# Create coordinator and solve
coordinator = CoordinatorAgent()
result = coordinator.solve_challenge(challenge.to_dict())
print(result)
```

### Viewing Results

```bash
# View all challenges
python view_results.py --list

# View specific challenge
python view_results.py --challenge-id web_001

# View flags captured
python view_results.py --flags

# Generate report
python view_results.py --report --output report.md
```

## Directory Structure

Understanding the directory structure will help you navigate the system:

```
CTF_Agents/
├── agents/           # Agent implementations
├── core/            # Core system components
├── tools/           # Tool wrappers and utilities
├── config/          # Configuration files
├── challenges/      # Challenge management
├── shared/          # Shared resources
├── logs/            # System logs
├── results/         # Challenge results
├── tests/           # Test suite
└── docs/            # Documentation
```

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

1. **Submit Challenge**
   ```bash
   python submit_challenge.py --file challenge.json
   ```

2. **Monitor Progress**
   ```bash
   tail -f logs/system/system.log
   ```

3. **View Results**
   ```bash
   python view_results.py --challenge-id <id>
   ```

4. **Review Solution**
   - Check `results/reports/` for detailed report
   - Check `results/flags/` for captured flag
   - Check `results/artifacts/` for generated files

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
# Run with sudo (not recommended for production)
sudo python main.py

# Or configure tools to run with appropriate permissions
```

### Import Errors

If you encounter import errors:
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

## Next Steps

- Read the [Architecture Overview](../architecture/system_overview.md)
- Learn about [Agent Development](../agents/development_guide.md)
- Explore [Configuration Options](configuration.md)
- Check out [Example Challenges](../../challenges/templates/)

## Getting Help

- Check the [FAQ](faq.md)
- Read the [Troubleshooting Guide](troubleshooting.md)
- Open an issue on GitHub
- Join our community Discord/Slack

## Contributing

We welcome contributions! See [Contributing Guide](contributing.md) for details.

---

Happy hacking! 🚀

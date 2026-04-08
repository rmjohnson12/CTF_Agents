This repository is my fork of the CTF_Agents project originally created by TonyZeroArch.

My contributions:
-  Built modular Python tooling to support automated CTF challenge analysis
-  Implemented cryptography agent capable of Caesar detection and brute-force decryption workflows
-  Developed reusable network tooling modules (Nmap integration, structured results pipeline)
-  Created tool execution layer and testing framework using pytest
-  Contributed to architecture for agent-driven challenge solving and structured output handling
-  Added minimal execution entrypoint

# CTF_Agents

A hierarchical multi-agent system for solving Capture The Flag (CTF) challenges using AI-driven autonomy. This system mimics a human CTF team structure with specialized agents working together to tackle diverse challenges across multiple categories.

## 🎯 Overview

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/TonyZeroArch/CTF_Agents)

CTF_Agents is a modular, multi-agent system designed to autonomously solve CTF challenges across various categories including:
- **Web Exploitation**: XSS, SQLi, CSRF, SSRF, etc.
- **Cryptography**: Classical and modern ciphers, hashing, encoding
- **Reverse Engineering**: Binary analysis, decompilation, debugging
- **Forensics**: Memory analysis, disk forensics, steganography
- **Binary Exploitation**: Buffer overflows, ROP, shellcode
- **OSINT**: Open-source intelligence gathering
- **PWN**: Exploitation and exploit development
- **Miscellaneous**: Challenges that don't fit standard categories
- **Networking**: Protocol analysis, packet manipulation

## 🏗️ Architecture

The system follows a hierarchical multi-agent architecture:

```
                    ┌─────────────────┐
                    │   Coordinator   │
                    │     Agent       │
                    └────────┬────────┘
                             │
                ┌────────────┼────────────┐
                │            │            │
        ┌───────▼─────┐ ┌───▼──────┐ ┌──▼────────┐
        │ Specialist  │ │Specialist│ │  Support  │
        │   Agents    │ │  Agents  │ │  Agents   │
        └─────────────┘ └──────────┘ └───────────┘
```

### Core Components

- **Coordinator Agent**: Central decision-maker that analyzes challenges, assigns tasks, and orchestrates the system
- **Specialist Agents**: Domain experts for specific CTF categories
- **Support Agents**: Auxiliary services like reconnaissance and vulnerability scanning
- **Communication Layer**: Message routing and event handling
- **Knowledge Base**: Shared intelligence and historical data
- **Decision Engine**: Strategic planning and agent coordination

## 📁 Project Structure

```
CTF_Agents/
├── agents/                    # All agent implementations
│   ├── coordinator/          # Central coordinator agent
│   ├── specialists/          # Category-specific specialist agents
│   │   ├── web_exploitation/
│   │   ├── cryptography/
│   │   ├── reverse_engineering/
│   │   ├── forensics/
│   │   ├── binary_exploitation/
│   │   ├── osint/
│   │   ├── pwn/
│   │   ├── misc/
│   │   └── networking/
│   └── support/              # Support and auxiliary agents
│       ├── reconnaissance/
│       ├── exploit_development/
│       └── vulnerability_scanner/
│
├── core/                      # Core system components
│   ├── communication/        # Inter-agent communication
│   ├── task_manager/         # Task queue and assignment
│   ├── knowledge_base/       # Shared knowledge storage
│   └── decision_engine/      # Strategic decision-making
│
├── tools/                     # CTF tools and utilities
│   ├── web/                  # Web exploitation tools
│   ├── crypto/               # Cryptography tools
│   ├── reversing/            # Reverse engineering tools
│   ├── forensics/            # Forensics tools
│   ├── binary/               # Binary exploitation tools
│   ├── network/              # Network analysis tools
│   └── common/               # Common utilities
│
├── shared/                    # Shared resources
│   ├── payloads/             # Exploit payloads
│   ├── wordlists/            # Attack dictionaries
│   ├── exploits/             # Reusable exploits
│   ├── scripts/              # Utility scripts
│   └── models/               # AI/ML models
│
├── challenges/                # Challenge management
│   ├── active/               # Currently active challenges
│   ├── completed/            # Solved challenges
│   └── templates/            # Challenge templates
│
├── config/                    # Configuration files
│   └── README.md             # Configuration documentation
│
├── logs/                      # System logs
│   ├── agents/               # Agent-specific logs
│   ├── challenges/           # Challenge logs
│   └── system/               # System-wide logs
│
├── results/                   # Challenge results
│   ├── reports/              # Solution reports
│   ├── flags/                # Captured flags
│   └── artifacts/            # Challenge artifacts
│
├── tests/                     # Test suite
│   ├── unit/                 # Unit tests
│   ├── integration/          # Integration tests
│   └── mocks/                # Mock objects and fixtures
│
└── docs/                      # Documentation
    ├── architecture/         # Architecture documentation
    ├── agents/               # Agent documentation
    ├── guides/               # User and developer guides
    └── api/                  # API documentation
```

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Docker (for containerized tools)
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/TonyZeroArch/CTF_Agents.git
cd CTF_Agents

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure the system
cp config/config.example.yaml config/config.yaml
# Edit config.yaml with your settings
```

### Quick Start

```bash
# Start the system
python main.py

# Submit a challenge
python submit_challenge.py --file challenge.zip --category web

# View results
python view_results.py --challenge-id <id>
```

## 🔧 Configuration

System configuration is managed through YAML files in the `config/` directory:

- `system_config.yaml`: Main system settings
- `agents_config.yaml`: Agent-specific configurations
- `tools_config.yaml`: Tool settings and paths
- `communication_config.yaml`: Message routing configuration

See `config/README.md` for detailed configuration options.

## 🤖 Agent Development

To create a new specialist agent:

1. Create agent directory under `agents/specialists/`
2. Implement the agent interface
3. Register agent in configuration
4. Add agent-specific tools
5. Write tests

See `docs/agents/development_guide.md` for detailed instructions.

## 🧪 Testing

```bash
# Run all tests
pytest

# Run specific test category
pytest tests/unit/
pytest tests/integration/

# Run with coverage
pytest --cov=agents --cov=core --cov=tools
```

## 📊 Monitoring

The system provides comprehensive logging and monitoring:

- Agent activity logs in `logs/agents/`
- Challenge progress in `logs/challenges/`
- System metrics in `logs/system/`

## 🔒 Security & Ethics

This system is designed for:
- Authorized CTF competitions
- Security research with permission
- Educational purposes

**Never use against real systems without explicit authorization.**

## 📚 Documentation

Comprehensive documentation is available in the `docs/` directory:

- [Architecture Overview](docs/architecture/system_overview.md)
- [Agent Development Guide](docs/agents/development_guide.md)
- [Configuration Guide](docs/guides/configuration.md)
- [API Documentation](docs/api/)

## 🤝 Contributing

Contributions are welcome! Please see `docs/guides/contributing.md` for guidelines.

## 📝 License

This project is licensed under the terms specified in the LICENSE file.

## 🙏 Acknowledgments

- Inspired by hierarchical multi-agent systems research
- Built for the CTF community
- Powered by AI and automation

## 📧 Contact

For questions or feedback, please open an issue on GitHub.

---

**Note**: This is a framework for autonomous CTF challenge solving. Effectiveness depends on agent implementation, tool integration, and continuous learning from challenges.

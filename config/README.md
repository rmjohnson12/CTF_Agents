# Configuration Directory

This directory contains configuration files for the multi-agent CTF system.

## Configuration Files

### System Configuration
- `system_config.yaml`: Main system configuration
  - Agent settings
  - Resource limits
  - Timeouts
  - Logging levels
  - Performance tuning

### Agent Configuration
- `agents_config.yaml`: Agent-specific settings
  - Agent capabilities and expertise
  - Priority levels
  - Concurrent task limits
  - Specialization parameters

### Tool Configuration
- `tools_config.yaml`: Tool settings
  - Tool paths and installations
  - API keys and credentials (via environment variables)
  - Tool-specific parameters
  - Timeout values

## Environment Variables

Secrets belong in environment variables, never in the YAML files above:
- Provider API keys
- External service credentials
- Live-reporting tokens

Copy the repository-root `.env.example` to `.env` for local API keys and
provider selection. The root `.env` is the only environment file the runtime
loads; there is no `config/.env`.

## Configuration Hierarchy

Configuration priority (highest to lowest):
1. Environment variables
2. Command-line arguments
3. Local configuration files
4. Default configuration

## Example Structure

See `system_config.yaml` for the live schema. It is not reproduced here, so the
two cannot drift apart.

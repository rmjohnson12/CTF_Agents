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

### Communication Configuration
- `communication_config.yaml`: Message routing and protocols
  - Message broker settings
  - Queue configurations
  - Event subscriptions
  - Retry policies

### Knowledge Base Configuration
- `knowledge_base_config.yaml`: Database and storage settings
  - Database connection strings
  - Cache configurations
  - Index settings
  - Backup policies

## Environment Variables

Sensitive configuration should use environment variables:
- API keys
- Database passwords
- External service credentials
- Secret tokens

Example `.env.example` file should be provided for reference.

## Configuration Hierarchy

Configuration priority (highest to lowest):
1. Environment variables
2. Command-line arguments
3. Local configuration files
4. Default configuration

## Example Structure

```yaml
# system_config.yaml
system:
  name: "CTF Multi-Agent System"
  version: "1.0.0"
  max_concurrent_challenges: 5
  log_level: "INFO"
  
coordinator:
  strategy: "hierarchical"
  decision_threshold: 0.8
  timeout_minutes: 30
  
performance:
  enable_caching: true
  parallel_agents: true
  max_threads: 10
```

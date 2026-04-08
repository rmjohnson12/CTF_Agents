# Logs Directory

This directory contains system and operational logs for monitoring and debugging.

## Structure

### agents/
Individual agent logs:
- Agent initialization and shutdown
- Task assignments received
- Actions taken
- Tool executions
- Errors and exceptions
- Communication events
- Performance metrics

### challenges/
Challenge-specific logs:
- Challenge lifecycle events
- Solution attempts
- Tool outputs
- Error messages
- State transitions
- Agent assignments

### system/
System-wide operational logs:
- System startup/shutdown
- Configuration changes
- Resource utilization
- Performance metrics
- Error tracking
- Security events
- Communication flow

## Log Formats

### Standard Log Entry
```json
{
  "timestamp": "2024-01-08T14:20:00Z",
  "level": "INFO",
  "component": "coordinator",
  "message": "Assigned challenge web_001 to web_agent",
  "context": {
    "challenge_id": "web_001",
    "agent_id": "web_agent_01",
    "priority": "high"
  }
}
```

### Log Levels
- **DEBUG**: Detailed information for debugging
- **INFO**: General informational messages
- **WARNING**: Warning messages for potential issues
- **ERROR**: Error messages for failures
- **CRITICAL**: Critical issues requiring immediate attention

## Log Rotation

Logs should be:
- Rotated daily or by size (e.g., 100MB)
- Compressed after rotation
- Retained for configurable period (e.g., 30 days)
- Archived for long-term storage if needed

## Log Analysis

Use logs for:
- Debugging issues
- Performance analysis
- Agent behavior analysis
- System monitoring
- Audit trails
- Pattern detection

## Configuration Example

```yaml
# logging_config.yaml
logging:
  level: INFO
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  rotation:
    max_bytes: 104857600  # 100MB
    backup_count: 10
  paths:
    agents: "logs/agents/"
    challenges: "logs/challenges/"
    system: "logs/system/"
```

## Monitoring Tools

Consider integrating:
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Grafana for visualization
- Prometheus for metrics
- Sentry for error tracking

## Best Practices

1. Use structured logging (JSON format)
2. Include relevant context in log entries
3. Avoid logging sensitive information
4. Use appropriate log levels
5. Implement log aggregation for distributed systems
6. Set up alerts for critical errors
7. Regular log analysis for patterns

# Core System Components

This directory contains the core infrastructure components that enable the multi-agent system to function.

## Components

### Communication
Handles inter-agent communication and message routing:
- Message broker/queue system
- Event bus for system-wide events
- Protocol definitions for agent messages
- Communication interfaces and APIs

### Task Manager
Manages challenge tasks and agent assignments:
- Task queue and prioritization
- Task assignment to agents
- Progress tracking
- Dependency management
- Resource allocation

### Knowledge Base
Centralized storage for shared knowledge:
- Challenge information and metadata
- Discovered vulnerabilities
- Exploit techniques and patterns
- Historical performance data
- Agent expertise profiles
- CTF-specific knowledge graphs

### Decision Engine
Strategic decision-making system:
- Challenge classification and routing
- Strategy selection and planning
- Risk assessment
- Success probability estimation
- Agent performance evaluation
- Dynamic replanning based on results

## Integration

These components work together to:
1. Receive and analyze CTF challenges
2. Coordinate agent activities
3. Share information across the system
4. Make intelligent decisions about approach strategies
5. Learn from past attempts

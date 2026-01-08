# Agents Directory

This directory contains all agent implementations for the hierarchical multi-agent CTF system.

## Structure

### Coordinator
The coordinator agent acts as the central decision-maker and orchestrator for the entire system. It:
- Analyzes incoming CTF challenges
- Assigns tasks to specialist agents
- Monitors progress and coordinates inter-agent communication
- Aggregates results and makes strategic decisions
- Manages resource allocation

### Specialists
Specialized agents focused on specific CTF challenge categories:

- **web_exploitation**: Web security vulnerabilities (XSS, SQLI, CSRF, etc.)
- **cryptography**: Encryption, hashing, encoding challenges
- **reverse_engineering**: Binary analysis and code reverse engineering
- **forensics**: Memory dumps, disk images, network captures
- **binary_exploitation**: Buffer overflows, ROP chains, shellcode
- **osint**: Open-source intelligence gathering
- **pwn**: Exploitation challenges and exploit development
- **misc**: Miscellaneous challenges that don't fit other categories
- **networking**: Network protocols, packet analysis

### Support
Support agents that provide auxiliary services:

- **reconnaissance**: Initial information gathering and enumeration
- **exploit_development**: Creating and testing exploits
- **vulnerability_scanner**: Automated vulnerability detection

## Agent Communication

Agents communicate through the core communication system using:
- Message queues for asynchronous communication
- Shared knowledge base for information exchange
- Event-driven architecture for real-time updates

## Agent Development

Each agent should implement:
1. Challenge analysis capabilities
2. Strategy formulation
3. Tool execution
4. Result validation
5. Knowledge sharing

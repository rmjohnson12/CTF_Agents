# Challenges Directory

This directory manages CTF challenges throughout their lifecycle.

## Structure

### active/
Currently active challenges being worked on:
- Challenge metadata and descriptions
- Current progress and status
- Agent assignments
- Attempted solutions
- Intermediate findings

### completed/
Successfully solved challenges:
- Final solutions and write-ups
- Flags captured
- Techniques used
- Lessons learned
- Performance metrics

### templates/
Challenge templates and examples:
- Challenge format specifications
- Input/output templates
- Category-specific templates
- Integration examples

## Challenge Lifecycle

1. **Intake**: New challenge received and parsed
2. **Analysis**: Initial analysis and categorization
3. **Assignment**: Routed to appropriate specialist agents
4. **Solving**: Active work by agents
5. **Validation**: Solution verification
6. **Completion**: Flag submission and documentation

## Challenge Format

Each challenge directory should contain:
```
challenge_name/
├── metadata.json       # Challenge information
├── description.md      # Full challenge description
├── files/             # Challenge files
├── attempts/          # Solution attempts
├── solution/          # Final solution
└── writeup.md        # Documentation
```

## Metadata Schema

```json
{
  "name": "Challenge Name",
  "category": "web/crypto/pwn/etc",
  "difficulty": "easy/medium/hard",
  "points": 100,
  "description": "Challenge description",
  "hints": [],
  "files": [],
  "tags": [],
  "status": "active/completed/failed",
  "assigned_agents": [],
  "start_time": "ISO8601",
  "completion_time": "ISO8601",
  "flag": "CTF{flag_here}"
}
```

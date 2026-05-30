# PWN Agent

Specialist agent for binary exploitation challenges, including HackTheBox pwn and CTF categories.

## Solve Pipeline

The agent works through five phases in order, stopping as soon as a flag is confirmed:

1. **checksec** — identify mitigations (NX, PIE, stack canary, RELRO)
2. **Ghidra headless analysis** — extract functions, strings, and imports (requires `GHIDRA_HOME`)
3. **angr symbolic execution** — locate win/flag symbols and derive stdin payload
   - 3b. Run binary locally with the payload, scan output for a flag pattern
   - 3c. If no local flag and `connection_info` is present, send payload to the remote server
4. **ret2win** — classic stack overflow exploitation (see below)
5. **pwntools template + LLM strategy** — generate an exploit scaffold and request advisory from the configured LLM

## Phase 4: ret2win

Handles the common HTB/CTF pattern where a binary has a reachable win function and a simple stack overflow:

1. **PIE check** (`readelf -h`) — skips if the binary is position-independent (static addresses are invalid)
2. **Win function discovery** (`nm`, `objdump -t`) — looks for functions named `win`, `flag`, `shell`, `backdoor`, `success`, or `correct`
3. **Overflow offset** — uses pwntools `cyclic` + core dump; falls back to brute-forcing common offsets (40, 56, 72 … 256) if core dumps are unavailable
4. **ret gadget** (`ROPgadget --only ret`, `objdump -d`) — finds a bare `ret` for x86-64 stack alignment before the win call
5. **Payload delivery** — tries locally first, then sends to the remote via pwntools if `connection_info` is provided

## Tools Used

| Tool | Purpose |
|------|---------|
| pwntools | Remote I/O, cyclic pattern generation, core dump analysis |
| checksec | Mitigation detection |
| nm / objdump | Symbol and gadget extraction |
| ROPgadget | ret gadget lookup |
| readelf | PIE detection |
| angr | Symbolic execution (optional, `pip install angr`) |
| Ghidra headless | Static analysis (optional, set `GHIDRA_HOME`) |

## Challenge Input Format

```json
{
  "id": "challenge-id",
  "category": "pwn",
  "description": "Exploit the buffer overflow...",
  "files": ["./vuln"],
  "connection_info": "1.2.3.4:31337"
}
```

`connection_info` is optional. When present, confirmed payloads are also sent to the remote server.

## Environment Variables

| Variable | Effect |
|----------|--------|
| `GHIDRA_HOME` | Enables Ghidra headless analysis |

## Common Techniques Handled

- ret2win (win function + stack overflow)
- angr-guided symbolic execution for complex path conditions
- x86-64 stack alignment via ret gadget
- Remote payload delivery with banner/prompt handling

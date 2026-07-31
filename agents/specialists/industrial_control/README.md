# Industrial Control Agent

`ics_agent` handles Industrial Control System and Operational Technology
challenges involving PLCs, HMIs, ladder logic, and industrial protocols.

## Implemented deterministic path

The first playbook supports the water-storage process used by Hack The Box
Factory. It validates the challenge name/description or the paired
`interface_setup.png` and `PLC_Ladder_Logic.pdf` artifacts before it sends any
write. The sequence is derived from the ladder logic:

1. Set `manual_mode_control`, then pulse `start` to enter manual mode.
2. Set `cutoff_in` to stop inflow.
3. Set `force_start_out` to open the outlet.
4. Read status and accept a flag only after the process reports manual mode,
   inlet closed, and outlet open.

Frames use Modbus RTU function 5 (write single coil) without a CRC because the
challenge relay adds it. This path is deterministic and works with
`LLM_PROVIDER=none`.

## Safety boundaries

- Remote hosts must pass `CTF_AGENTS_ALLOWED_NETWORKS` policy.
- Only the four evidence-backed Factory coils are writable.
- Responses are capped at 64 KiB and socket operations are timeout bounded.
- A failed mode transition stops later actuator writes.
- Generic ICS challenges are analyzed but receive no write unless a supported
  playbook matches.

Run the offline contract tests with:

```bash
LLM_PROVIDER=none python3 -m pytest -q tests/unit/test_ics_agent.py tests/e2e/test_golden_examples.py
```

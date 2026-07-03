# Operator's Guide

## Inspect before executing

Use plan mode to confirm category, evidence, selected agent, and first action:

```bash
python3 ask.py --plan "Web challenge at http://TARGET:PORT"
```

## Run one challenge

```bash
CTF_AGENTS_ALLOWED_NETWORKS=TARGET \
  python3 ask.py "Authorized web challenge at http://TARGET:PORT"
```

The final status distinguishes `solved`, `attempted`, and `failed`. Review the
recent steps and persisted report before retrying.

## Resume

Structured challenges can resume from `logs/checkpoints/<challenge_id>.json`:

```bash
python3 main.py challenge.json --resume
```

Resume is useful only when the target and artifacts still match the checkpoint.

## Campaigns and benchmarks

```bash
python3 campaign.py challenges/active --limit 5 --max-attempts 2
python3 campaign.py challenges/benchmarks/manifest.json \
  --json-out results/benchmark.json \
  --markdown-out results/benchmark.md
```

Campaigns are local and bounded. The default provider does not authenticate to
CTF platforms, start remote instances, or submit flags.

## Solve-trace memory

Successful runs persist compact routing, artifact, and technique metadata in
`logs/solve_traces.db`; raw flags and private keys are not stored. Similar
future challenges receive the matched route and technique names directly in
their specialist context. Aggregate success rates in `logs/performance.db` are
telemetry only and cannot reconstruct a prior exploit by themselves.

## Word-embedding models

The coding specialist can solve complete `Like A is to B, C is to?` text
artifacts with supported Gensim GloVe Twitter models. Existing cached models are
used automatically. To explicitly permit the first model download, run:

```bash
CTF_AGENTS_ALLOW_MODEL_DOWNLOAD=1 \
  python3 ask.py "Solve chal.txt with glove-twitter-25"
```

Model names are restricted to the supported GloVe Twitter variants; arbitrary
challenge text cannot select another download.

## Raw TCP Forth diagnostics

For an authorized hardware target that exposes a Forth diagnostic interpreter,
provide the host and port in the instruction and allowlist that host explicitly:

```bash
CTF_AGENTS_ALLOWED_NETWORKS=TARGET_IP/32 \
  python3 ask.py \
  "Hardware challenge: the diagnostic terminal runs Forth at TARGET_IP:PORT"
```

The hardware specialist enters the diagnostic menu, enumerates `words`, and
continues only if the dictionary exposes `system`. It reports the selected
agent and each evidence gate in the normal routing and step output.

Keep the connection open while interacting with menu-driven services. Some
challenge binaries loop rapidly when their input reaches EOF, so one-shot
pipelines such as `printf ... | nc ...` can produce misleading output or kill
an ephemeral instance.

## Remote ARM instruction challenges

The reverse specialist recognizes evidence-gated challenges that stream raw
A32 instructions and request the final value of register `r0`. A local file is
not required. Provide and explicitly allowlist the authorized target:

```bash
CTF_AGENTS_ALLOWED_NETWORKS=TARGET_IP/32 \
  python3 ask.py \
  "Reversing challenge: emulate raw ARM instructions and return r0 at TARGET_IP:PORT"
```

Each level runs in a fresh Unicorn emulator. Level counts, transcript size,
machine-code size, instruction count, connection time, and target access are
bounded. Progress events are emitted at useful intervals for live reporting.

## Troubleshooting

1. Run `python3 check_setup.py`.
2. Re-run with `--plan` and inspect routing evidence.
3. Check the final failure reason and tool availability.
4. Separate target failures from local policy failures.
5. Use focused tests before changing a specialist.

Do not respond to a policy error by globally disabling network or execution
controls.

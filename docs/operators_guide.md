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

## Troubleshooting

1. Run `python3 check_setup.py`.
2. Re-run with `--plan` and inspect routing evidence.
3. Check the final failure reason and tool availability.
4. Separate target failures from local policy failures.
5. Use focused tests before changing a specialist.

Do not respond to a policy error by globally disabling network or execution
controls.

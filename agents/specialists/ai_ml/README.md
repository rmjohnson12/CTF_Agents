# AI/ML Specialist

`ai_ml_agent` handles adversarial AI/ML challenges, beginning with bounded
prompt-leaking workflows for multi-level chatbots.

The current playbook validates an HTTP client contract containing `/process`,
`/verify`, JWT/CSRF session state, and an explicit level marker. It then tries
four reviewed disclosure transformations per level. Only words present in the
model response are submitted to the verification endpoint; verification is
capped at six candidates per level and eight levels total. A flag is accepted
only from `/verify`, never from untrusted model output.

Targets must pass the shared network allowlist. Result artifacts retain counts
and technique names, but do not retain level passwords or other disclosed
secrets. The complete five-level session is exercised offline in
`tests/unit/test_ai_ml_agent.py`.

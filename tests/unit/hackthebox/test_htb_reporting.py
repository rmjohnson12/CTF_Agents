import json
from pathlib import Path

from integrations.hackthebox.models import Challenge, ChallengeAttempt, RunReport, SpawnInfo
from integrations.hackthebox.reporting import render_markdown, write_reports, default_report_path


def _report(dry_run=False):
    ch = Challenge(id=42, name="Alpha", category="web", difficulty="easy",
                   has_download=True, needs_instance=True, description="a desc")
    attempt = ChallengeAttempt(
        challenge=ch,
        started=True,
        spawn=SpawnInfo(challenge_id=42, ip="10.0.0.1", port=80, status="running"),
        downloaded_files=["runs/htb/42-alpha/a.txt"],
        work_dir="runs/htb/42-alpha",
        solver_status="solved",
        solver_steps=["step one", "found HTB{x}"],
        candidate_flags=["HTB{x}"],
        dry_run=dry_run,
        duration_seconds=1.5,
    )
    return RunReport(
        timestamp="2026-07-03T10:00:00+00:00",
        user={"id": 5, "name": "me"},
        filters={"category": "web"},
        dry_run=dry_run,
        submit_enabled=False,
        attempts=[attempt],
        duration_seconds=2.0,
    )


def test_render_markdown_contains_key_fields():
    md = render_markdown(_report())
    assert "# Hack The Box automation run" in md
    assert "Alpha" in md and "#42" in md
    assert "HTB{x}" in md
    assert "10.0.0.1:80" in md
    assert "me" in md


def test_dry_run_label():
    assert "DRY-RUN" in render_markdown(_report(dry_run=True))
    assert "LIVE" in render_markdown(_report(dry_run=False))


def test_write_reports_creates_md_and_json(tmp_path):
    out = tmp_path / "reports" / "htb.md"
    md_path, json_path = write_reports(_report(), output_path=str(out))
    assert Path(md_path).exists()
    assert Path(json_path).exists() and json_path.endswith(".json")
    data = json.loads(Path(json_path).read_text())
    assert data["user"]["id"] == 5
    assert data["attempts"][0]["candidate_flags"] == ["HTB{x}"]


def test_default_report_path_is_timestamped():
    path = default_report_path(_report(), report_dir="reports")
    assert path.startswith("reports/htb_results_")
    assert path.endswith(".md")


def test_report_never_contains_raw_challenge_blob(tmp_path):
    report = _report()
    report.attempts[0].challenge.raw = {"secret_internal_field": "should-not-appear"}
    _, json_path = write_reports(report, output_path=str(tmp_path / "r.md"))
    assert "secret_internal_field" not in Path(json_path).read_text()

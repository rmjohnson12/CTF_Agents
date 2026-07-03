import zipfile
from pathlib import Path

import pytest

from integrations.hackthebox.config import HTBConfig
from integrations.hackthebox.challenge_runner import (
    ChallengeRunner,
    filter_challenges,
    extract_candidate_flags,
    is_htb_flag,
)
from integrations.hackthebox.errors import HTBError
from integrations.hackthebox.models import Challenge, SpawnInfo


def _ch(**kw):
    base = dict(id=1, name="C", category="web", difficulty="easy")
    base.update(kw)
    return Challenge(**base)


class FakeClient:
    def __init__(self, *, download=b"", spawn=None, submit_result=None, info=None):
        self.config = HTBConfig()
        self._download = download
        self._spawn = spawn
        self._submit_result = submit_result or {"message": "Correct"}
        self._info = info  # optional enriched Challenge
        self.calls = []

    def get_challenge(self, cid):
        self.calls.append(("info", cid))
        if self._info is None:
            raise HTBError("no info in fake")  # enrichment falls back to list data
        return self._info

    def download_challenge(self, cid):
        self.calls.append(("download", cid))
        if not self._download:
            raise HTBError("no download")
        return self._download

    def start_instance(self, cid):
        self.calls.append(("start", cid))
        if self._spawn is None:
            raise HTBError("no instance")
        return self._spawn

    def stop_instance(self, cid):
        self.calls.append(("stop", cid))
        return {"message": "stopped"}

    def submit_flag(self, cid, flag, difficulty=50):
        self.calls.append(("submit", cid, flag, difficulty))
        return self._submit_result


# ------------------------------------------------------------- filtering
def test_filter_by_category_and_max():
    chs = [_ch(id=1, category="web"), _ch(id=2, category="crypto"), _ch(id=3, category="web")]
    out = filter_challenges(chs, category="web", max_count=1)
    assert [c.id for c in out] == [1]


def test_filter_excludes_retired_solved_locked_by_default():
    chs = [
        _ch(id=1),
        _ch(id=2, retired=True),
        _ch(id=3, solved=True),
        _ch(id=4, locked=True),
    ]
    out = filter_challenges(chs)
    assert [c.id for c in out] == [1]


def test_filter_includes_when_requested():
    chs = [_ch(id=2, retired=True), _ch(id=3, solved=True), _ch(id=4, locked=True)]
    out = filter_challenges(chs, include_retired=True, include_solved=True, include_locked=True)
    assert {c.id for c in out} == {2, 3, 4}


# ------------------------------------------------------------- flags
def test_is_htb_flag():
    assert is_htb_flag("HTB{good}") is True
    assert is_htb_flag("htb{good}") is True
    assert is_htb_flag("CTF{nope}") is False


def test_extract_candidate_flags_prioritises_htb():
    out = extract_candidate_flags("CTF{a} noise HTB{b} more")
    assert out[0] == "HTB{b}"
    assert "CTF{a}" in out


# ------------------------------------------------------------- dry-run
def test_dry_run_performs_no_side_effects(tmp_path):
    client = FakeClient()
    runner = ChallengeRunner(client, base_dir=str(tmp_path / "runs"), solver_fn=_boom_solver)
    ch = _ch(has_download=True, needs_instance=True)

    attempts = runner.run([ch], dry_run=True)

    assert attempts[0].dry_run is True
    assert attempts[0].solver_status == "dry-run"
    # Dry-run may make read-only info calls but no MUTATING actions.
    mutating = [c for c in client.calls if c[0] in ("download", "start", "submit", "stop")]
    assert mutating == []
    assert not (tmp_path / "runs").exists()  # no work dir created


def _boom_solver(ctx):
    raise AssertionError("solver must not run during dry-run")


# ------------------------------------------------------------- real run
def _zip_bytes(tmp_path, members):
    p = tmp_path / "_a.zip"
    with zipfile.ZipFile(p, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    data = p.read_bytes()
    p.unlink()
    return data


def test_real_run_downloads_and_runs_solver_in_scope(tmp_path):
    captured = {}

    def solver(ctx):
        captured.update(ctx)
        return {"status": "solved", "flag": "HTB{found}", "steps": ["did the thing", "flag HTB{found}"]}

    client = FakeClient(download=_zip_bytes(tmp_path, {"chall.txt": "data"}))
    runner = ChallengeRunner(client, base_dir=str(tmp_path / "runs"), solver_fn=solver)
    ch = _ch(id=42, name="Alpha", has_download=True, needs_instance=False, description="desc")

    attempts = runner.run([ch], dry_run=False, do_start=True)
    a = attempts[0]

    assert a.solver_status == "solved"
    assert "HTB{found}" in a.candidate_flags
    assert a.submitted is False  # never submits without submit=True
    # solver scope: only HTB-provided files + (no) target were passed
    assert captured["category"] == "web"
    assert any(f.endswith("chall.txt") for f in captured["files"])
    assert captured["url"] is None
    assert ("submit", 42, "HTB{found}", 50) not in client.calls


def test_submit_only_when_enabled(tmp_path):
    def solver(ctx):
        return {"status": "solved", "flag": "HTB{f}", "steps": ["HTB{f}"]}

    client = FakeClient(download=_zip_bytes(tmp_path, {"a.txt": "x"}))
    runner = ChallengeRunner(client, base_dir=str(tmp_path / "runs"), solver_fn=solver)
    ch = _ch(id=7, has_download=True)

    runner.run([ch], dry_run=False, submit=True, submit_difficulty=30)

    assert ("submit", 7, "HTB{f}", 30) in client.calls


def test_spawn_target_passed_to_solver(tmp_path):
    captured = {}

    def solver(ctx):
        captured.update(ctx)
        return {"status": "attempted", "steps": []}

    spawn = SpawnInfo(challenge_id=9, ip="10.10.10.10", port=1337, status="running")
    client = FakeClient(spawn=spawn)
    runner = ChallengeRunner(
        client,
        base_dir=str(tmp_path / "runs"),
        solver_fn=solver,
        reachability_check=lambda host, port: True,  # no real network in tests
    )
    ch = _ch(id=9, needs_instance=True, has_download=False)

    attempts = runner.run([ch], dry_run=False, do_start=True, stop_started=True)

    assert attempts[0].started is True
    assert captured["url"] == "http://10.10.10.10:1337"
    assert ("stop", 9) in client.calls  # cleanup happened


def test_one_challenge_failure_does_not_abort_run(tmp_path):
    def solver(ctx):
        if ctx["name"] == "bad":
            raise RuntimeError("kaboom")
        return {"status": "solved", "flag": "HTB{ok}", "steps": ["HTB{ok}"]}

    client = FakeClient(download=_zip_bytes(tmp_path, {"a.txt": "x"}))
    runner = ChallengeRunner(client, base_dir=str(tmp_path / "runs"), solver_fn=solver)
    good = _ch(id=1, name="good", has_download=True)
    bad = _ch(id=2, name="bad", has_download=True)

    attempts = runner.run([bad, good], dry_run=False)

    assert attempts[0].error is not None and "kaboom" in attempts[0].error
    assert attempts[1].candidate_flags == ["HTB{ok}"]


def test_solver_timeout_is_recorded(tmp_path):
    import time

    def slow(ctx):
        time.sleep(2)
        return {"status": "solved"}

    client = FakeClient(download=_zip_bytes(tmp_path, {"a.txt": "x"}))
    runner = ChallengeRunner(client, base_dir=str(tmp_path / "runs"), solver_fn=slow, solver_timeout_seconds=0.2)
    ch = _ch(id=1, has_download=True)

    attempts = runner.run([ch], dry_run=False)
    assert attempts[0].solver_status == "timeout"


def test_filter_by_name_substring_case_insensitive():
    chs = [_ch(id=1, name="The Suspicious Domain"), _ch(id=2, name="Other")]
    out = filter_challenges(chs, name_contains="suspicious domain")
    assert [c.id for c in out] == [1]


def test_filter_by_exact_id():
    chs = [_ch(id=10), _ch(id=11), _ch(id=12)]
    out = filter_challenges(chs, challenge_id=11)
    assert [c.id for c in out] == [11]


def test_name_filter_can_include_retired_and_solved():
    chs = [_ch(id=1, name="The Suspicious Domain", retired=True, solved=True)]
    # excluded by default retired/solved rules...
    assert filter_challenges(chs, name_contains="suspicious") == []
    # ...but selectable when explicitly included (as the CLI does for --name).
    out = filter_challenges(chs, name_contains="suspicious", include_retired=True, include_solved=True)
    assert [c.id for c in out] == [1]


def test_enrichment_fills_missing_metadata(tmp_path):
    # List said no instance; info endpoint says it needs one -> runner must use info.
    enriched = _ch(id=973, name="The Suspicious Domain", category="OSINT",
                   needs_instance=True, description="Investigate the domain.")
    spawn = SpawnInfo(challenge_id=973, ip="10.10.10.5", port=80, status="running")
    client = FakeClient(spawn=spawn, info=enriched)
    seen = {}

    def solver(ctx):
        seen.update(ctx)
        return {"status": "attempted", "steps": []}

    runner = ChallengeRunner(client, base_dir=str(tmp_path / "runs"), solver_fn=solver,
                             reachability_check=lambda h, p: True)
    list_view = _ch(id=973, name="The Suspicious Domain", needs_instance=False)  # stale list data

    attempts = runner.run([list_view], dry_run=False, do_start=True)

    assert attempts[0].started is True  # enrichment corrected needs_instance -> spawned
    assert seen["description"] == "Investigate the domain."
    assert seen["url"] == "http://10.10.10.5:80"


def test_solver_skipped_when_instance_unavailable(tmp_path):
    # needs_instance but start fails (spawn=None) and no download -> skip solver.
    def solver(ctx):
        raise AssertionError("solver must not run when there is no target/artifact")

    client = FakeClient(spawn=None)  # start_instance raises -> no spawn
    runner = ChallengeRunner(client, base_dir=str(tmp_path / "runs"), solver_fn=solver)
    ch = _ch(id=954, name="Agriweb", needs_instance=True, has_download=False)

    attempts = runner.run([ch], dry_run=False, do_start=True)

    assert attempts[0].started is False
    assert attempts[0].solver_status == "skipped: no reachable target"
    assert attempts[0].candidate_flags == []


def test_solver_authorizes_only_instance_host_temporarily(tmp_path, monkeypatch):
    import os
    monkeypatch.setenv("CTF_AGENTS_ALLOWED_NETWORKS", "127.0.0.1")
    seen = []

    def solver(_ctx):
        seen.extend(os.environ["CTF_AGENTS_ALLOWED_NETWORKS"].split(","))
        return {"status": "attempted", "steps": []}

    spawn = SpawnInfo(challenge_id=1, ip="1.2.3.4", port=80)
    client = FakeClient(spawn=spawn)
    runner = ChallengeRunner(
        client, base_dir=str(tmp_path / "runs"), solver_fn=solver,
        reachability_check=lambda _host, _port: True,
    )
    runner.run([_ch(id=1, needs_instance=True)], dry_run=False, do_start=True)

    assert seen == ["127.0.0.1", "1.2.3.4"]
    assert os.environ["CTF_AGENTS_ALLOWED_NETWORKS"] == "127.0.0.1"


def test_solver_target_builds_http_url():
    assert ChallengeRunner._solver_target(SpawnInfo(challenge_id=1, ip="1.2.3.4", port=8080)) == "http://1.2.3.4:8080"
    assert ChallengeRunner._solver_target(None) is None

from core.utils.result_manager import ResultManager


def test_result_manager_prunes_reports_after_save(tmp_path):
    manager = ResultManager(base_results_dir=str(tmp_path), max_reports=2)

    for i in range(4):
        manager.save_run_result({
            "challenge_id": "prune_me",
            "status": "attempted",
            "iterations": i,
        })

    reports = list((tmp_path / "prune_me" / "reports").glob("run_*.json"))
    assert len(reports) == 2


def test_result_manager_uses_env_default_for_report_retention(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_MAX_REPORTS", "1")
    manager = ResultManager(base_results_dir=str(tmp_path))

    for i in range(3):
        manager.save_run_result({
            "challenge_id": "env_prune",
            "status": "attempted",
            "iterations": i,
        })

    reports = list((tmp_path / "env_prune" / "reports").glob("run_*.json"))
    assert len(reports) == 1

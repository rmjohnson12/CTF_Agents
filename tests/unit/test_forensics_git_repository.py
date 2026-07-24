from agents.specialists.forensics.forensics_agent import ForensicsAgent


def test_forensics_agent_identifies_git_repository_for_ai_recovery(tmp_path):
    repository = tmp_path / "memento"
    (repository / ".git").mkdir(parents=True)

    result = ForensicsAgent().solve_challenge({
        "id": "git-history",
        "category": "forensics",
        "description": "Recover an erased rite from the archive's older skins.",
        "files": [str(repository)],
    })

    assert result["status"] == "attempted"
    assert result["flag"] is None
    assert any(
        "inspect its commit history and patches for deleted content" in step
        for step in result["steps"]
    )
    assert result["artifacts"]["archives"] == [{
        "file": str(repository),
        "type": "git_repository",
        "history_available": True,
    }]

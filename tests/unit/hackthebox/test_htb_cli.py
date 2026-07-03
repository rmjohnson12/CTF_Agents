import os

from integrations.hackthebox.cli import _load_env_files, build_parser
from integrations.hackthebox.models import HTBCredentials


def test_load_env_files_reads_htb_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HTB_TOKEN", raising=False)
    (tmp_path / ".htb.env").write_text("HTB_TOKEN=file-token\n")

    loaded = _load_env_files()

    assert ".htb.env" in loaded
    assert HTBCredentials.from_env().token == "file-token"


def test_exported_env_wins_over_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HTB_TOKEN", "shell-token")
    (tmp_path / ".htb.env").write_text("HTB_TOKEN=file-token\n")

    _load_env_files()

    # A real exported variable must not be overridden by the file.
    assert os.environ["HTB_TOKEN"] == "shell-token"


def test_no_env_file_is_fine(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert _load_env_files() == []


def test_parser_accepts_name_and_id():
    args = build_parser().parse_args(["--name", "The Suspicious Domain", "--dry-run"])
    assert args.name == "The Suspicious Domain"
    assert args.dry_run is True

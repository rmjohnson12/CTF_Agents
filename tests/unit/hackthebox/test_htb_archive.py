import stat
import zipfile
from pathlib import Path

import pytest

from integrations.hackthebox.archive import (
    safe_extract_zip,
    extract_download,
    looks_like_zip,
    UnsafeArchiveError,
)
from integrations.hackthebox.errors import HTBError


def _make_zip(path: Path, members: dict) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


def test_extracts_valid_zip(tmp_path):
    archive = _make_zip(tmp_path / "c.zip", {"a.txt": "hello", "sub/b.txt": "world"})
    dest = tmp_path / "out"
    extracted = safe_extract_zip(str(archive), str(dest))
    assert (dest / "a.txt").read_text() == "hello"
    assert (dest / "sub" / "b.txt").read_text() == "world"
    assert len(extracted) == 2


def test_rejects_path_traversal(tmp_path):
    archive = _make_zip(tmp_path / "evil.zip", {"../escape.txt": "pwned"})
    with pytest.raises(UnsafeArchiveError):
        safe_extract_zip(str(archive), str(tmp_path / "out"))
    assert not (tmp_path / "escape.txt").exists()


def test_rejects_absolute_path(tmp_path):
    archive = tmp_path / "abs.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("/etc/pwned", "x")
    with pytest.raises(UnsafeArchiveError):
        safe_extract_zip(str(archive), str(tmp_path / "out"))


def test_rejects_symlink_member(tmp_path):
    archive = tmp_path / "link.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "/etc/passwd")
    with pytest.raises(UnsafeArchiveError):
        safe_extract_zip(str(archive), str(tmp_path / "out"))


def test_zip_bomb_guard(tmp_path, monkeypatch):
    monkeypatch.setenv("HTB_MAX_EXTRACT_BYTES", "4")
    archive = _make_zip(tmp_path / "big.zip", {"a.txt": "way more than four bytes"})
    with pytest.raises(UnsafeArchiveError):
        safe_extract_zip(str(archive), str(tmp_path / "out"))


def test_bad_zip_raises_htberror(tmp_path):
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"not a zip at all")
    with pytest.raises(HTBError):
        safe_extract_zip(str(bad), str(tmp_path / "out"))


def test_looks_like_zip():
    assert looks_like_zip(b"PK\x03\x04rest") is True
    assert looks_like_zip(b"\x7fELF") is False


def test_extract_download_zip(tmp_path):
    archive_bytes = _read_zip_bytes(tmp_path, {"flag.txt": "HTB{x}"})
    files = extract_download(archive_bytes, str(tmp_path / "work"), filename_hint="c.zip")
    # saved archive + extracted file
    assert any(f.endswith("flag.txt") for f in files)


def test_extract_download_non_zip_saves_blob(tmp_path):
    files = extract_download(b"\x7fELFbinary", str(tmp_path / "work"), filename_hint="firmware.bin")
    assert len(files) == 1 and files[0].endswith("firmware.bin")
    assert Path(files[0]).read_bytes() == b"\x7fELFbinary"


def _read_zip_bytes(tmp_path: Path, members: dict) -> bytes:
    p = _make_zip(tmp_path / "_tmp.zip", members)
    data = p.read_bytes()
    p.unlink()
    return data

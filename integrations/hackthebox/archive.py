"""Safe handling of downloaded challenge archives.

HTB challenge downloads are attacker-influenced data (the challenge author
controls the archive), so extraction defends against:
  * path traversal / zip-slip (``../`` or absolute members escaping the dest),
  * symlink members that could redirect writes outside the sandbox,
  * accidental extraction of a non-archive blob.

Extraction is confined to a single destination directory; anything that would
write outside it aborts the extraction for that challenge.
"""
from __future__ import annotations

import logging
import os
import stat
import zipfile
from pathlib import Path
from typing import List, Optional

from .errors import HTBError

logger = logging.getLogger(__name__)

_DEFAULT_MAX_UNCOMPRESSED = 500 * 1024 * 1024


def _max_extract_bytes() -> int:
    """Zip-bomb guard limit, read at call time so it can be tuned via env."""
    raw = (os.getenv("HTB_MAX_EXTRACT_BYTES") or "").strip()
    if not raw:
        return _DEFAULT_MAX_UNCOMPRESSED
    try:
        return max(1, int(raw))
    except ValueError:
        return _DEFAULT_MAX_UNCOMPRESSED


class UnsafeArchiveError(HTBError):
    """An archive member would escape the destination or is otherwise unsafe."""


def looks_like_zip(data: bytes) -> bool:
    return data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def save_bytes(content: bytes, dest_path: str) -> str:
    path = Path(dest_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return str(path)


def _is_within(base: Path, target: Path) -> bool:
    try:
        target.relative_to(base)
        return True
    except ValueError:
        return False


def safe_extract_zip(archive_path: str, dest_dir: str, password: Optional[str] = None) -> List[str]:
    """Extract a zip into ``dest_dir``, rejecting anything that escapes it.

    Returns the list of extracted file paths. Raises ``UnsafeArchiveError`` on a
    traversal/symlink attempt, or ``HTBError`` on a corrupt/undecryptable archive.
    """
    dest = Path(dest_dir).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    extracted: List[str] = []

    try:
        zf = zipfile.ZipFile(archive_path)
    except zipfile.BadZipFile as exc:
        raise HTBError(f"Downloaded file is not a valid zip archive: {exc}") from exc

    with zf:
        limit = _max_extract_bytes()
        total = sum(max(0, info.file_size) for info in zf.infolist())
        if total > limit:
            raise UnsafeArchiveError(
                f"Refusing to extract archive: uncompressed size {total} exceeds limit "
                f"{limit} (set HTB_MAX_EXTRACT_BYTES to override)."
            )

        pwd = password.encode() if password else None
        for info in zf.infolist():
            name = info.filename
            # Reject absolute paths outright.
            if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
                raise UnsafeArchiveError(f"Absolute path in archive: {name!r}")
            target = (dest / name).resolve()
            if target != dest and not _is_within(dest, target):
                raise UnsafeArchiveError(f"Path traversal in archive member: {name!r}")

            # Reject symlinks (they could later redirect writes/reads outside dest).
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise UnsafeArchiveError(f"Symlink member is not allowed: {name!r}")

            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with zf.open(info, pwd=pwd) as src, open(target, "wb") as dst:
                    dst.write(src.read())
            except RuntimeError as exc:
                # Typically a wrong/missing password for an encrypted entry.
                raise HTBError(
                    f"Could not extract {name!r} (encrypted archive?): {exc}. "
                    "HTB challenge archives commonly use the password 'hackthebox'."
                ) from exc
            extracted.append(str(target))

    return extracted


def extract_download(content: bytes, dest_dir: str, filename_hint: str, password: Optional[str] = None) -> List[str]:
    """Persist a downloaded blob and, if it is a zip, safely extract it.

    Always returns the list of resulting on-disk file paths (the saved archive
    plus any extracted files, or just the saved blob for non-archives).
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    saved: List[str] = []

    if looks_like_zip(content):
        archive_path = str(dest / (filename_hint or "challenge") )
        if not archive_path.endswith(".zip"):
            archive_path += ".zip"
        save_bytes(content, archive_path)
        saved.append(archive_path)
        saved.extend(safe_extract_zip(archive_path, str(dest), password=password))
    else:
        blob_path = str(dest / (filename_hint or "challenge.bin"))
        save_bytes(content, blob_path)
        saved.append(blob_path)

    return saved

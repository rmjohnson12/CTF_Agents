from __future__ import annotations

import ipaddress
import os
import re
import socket
from pathlib import Path
from typing import Iterable, List
from urllib.parse import urlparse

import yaml


_SAFE_ID_RE = re.compile(r"[^A-Za-z0-9_.-]+")
_SYSTEM_CONFIG = Path("config/system_config.yaml")


class SecurityPolicyError(ValueError):
    """Raised when untrusted input violates a local security policy."""


def safe_slug(value: object, *, default: str = "unknown_challenge") -> str:
    """Return a filesystem-safe identifier without path separators."""
    slug = _SAFE_ID_RE.sub("_", str(value or default)).strip("._-")
    return slug or default


def safe_child_path(base_dir: Path, filename: str) -> Path:
    """Resolve a child path and verify it remains under base_dir."""
    base = base_dir.resolve()
    path = (base / filename).resolve()
    if path != base and base not in path.parents:
        raise SecurityPolicyError(f"path escapes base directory: {path}")
    return path


def safe_checkpoint_path(checkpoint_dir: Path, challenge_id: object) -> Path:
    return safe_child_path(checkpoint_dir, f"{safe_slug(challenge_id)}.json")


def minimal_subprocess_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Build a minimal env for challenge-facing subprocesses."""
    keep = {
        "PATH",
        "HOME",
        "TMPDIR",
        "TEMP",
        "TMP",
        "LANG",
        "LC_ALL",
        "VIRTUAL_ENV",
        "SYSTEMROOT",
        "WINDIR",
    }
    env = {key: value for key, value in os.environ.items() if key in keep and value}
    if extra:
        env.update({str(key): str(value) for key, value in extra.items()})
    return env


def _load_configured_networks() -> List[str]:
    try:
        data = yaml.safe_load(_SYSTEM_CONFIG.read_text()) or {}
    except Exception:
        data = {}
    configured = data.get("security", {}).get("allowed_networks", []) or []
    return [str(item).strip() for item in configured if str(item).strip()]


def _load_allowed_networks() -> List[str]:
    allowed = _load_configured_networks()
    extra = os.getenv("CTF_AGENTS_ALLOWED_NETWORKS", "")
    allowed.extend(item.strip() for item in extra.split(",") if item.strip())
    return allowed


def assert_url_allowed(url: str, *, allowed_networks: Iterable[str] | None = None) -> None:
    """Allow only URLs whose resolved host is present in the configured allowlist."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SecurityPolicyError(f"unsupported or malformed URL: {url}")

    allowed = list(allowed_networks) if allowed_networks is not None else _load_allowed_networks()
    if not allowed:
        return

    host = parsed.hostname.lower().rstrip(".")
    if _host_matches_allowed(host, allowed):
        return

    try:
        resolved_ips = {
            ipaddress.ip_address(result[4][0])
            for result in socket.getaddrinfo(host, parsed.port, proto=socket.IPPROTO_TCP)
        }
    except Exception as exc:
        raise SecurityPolicyError(f"could not resolve URL host {host!r}: {exc}") from exc

    if any(_ip_matches_allowed(ip, allowed) for ip in resolved_ips):
        return

    raise SecurityPolicyError(
        f"URL host {host!r} is not in allowed networks. "
        "Set CTF_AGENTS_ALLOWED_NETWORKS for authorized spawned targets."
    )


def _host_matches_allowed(host: str, allowed: Iterable[str]) -> bool:
    for entry in allowed:
        entry = entry.lower().strip().rstrip(".")
        if not entry:
            continue
        if entry == host:
            return True
        if entry.startswith("*.") and host.endswith(entry[1:]):
            return True
        if "/" not in entry and not _looks_like_ip(entry) and host == entry:
            return True
    return False


def _ip_matches_allowed(ip: ipaddress._BaseAddress, allowed: Iterable[str]) -> bool:
    for entry in allowed:
        entry = entry.strip()
        if not entry:
            continue
        if entry.lower() == "localhost" and ip.is_loopback:
            return True
        try:
            if "/" in entry and ip in ipaddress.ip_network(entry, strict=False):
                return True
            if "/" not in entry and ip == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

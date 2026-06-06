from __future__ import annotations

import ipaddress
import os
import re
import socket
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator, List
from urllib.parse import urlparse

import yaml


_SAFE_ID_RE = re.compile(r"[^A-Za-z0-9_.-]+")
_SYSTEM_CONFIG = Path("config/system_config.yaml")


class SecurityPolicyError(ValueError):
    """Raised when untrusted input violates a local security policy."""


_SENSITIVE_KEY_RE = re.compile(
    r"(cookie|local_storage|session_storage|authorization|private[_-]?key|"
    r"api[_-]?key|token|secret|password|credential|session)",
    re.IGNORECASE,
)
_PRIVATE_KEY_VALUE_RE = re.compile(
    r"(?:0x)?[0-9a-fA-F]{64}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
)


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


def capture_sensitive_artifacts_enabled() -> bool:
    return os.getenv("CTF_AGENTS_CAPTURE_SENSITIVE_ARTIFACTS") == "1"


def redact_sensitive_data(value: Any) -> Any:
    """Recursively redact secrets before persistence or broad publication."""
    return _redact_sensitive_data(value, parent_key="")


def _redact_sensitive_data(value: Any, *, parent_key: str) -> Any:
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            key_s = str(key)
            if _SENSITIVE_KEY_RE.search(key_s):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = _redact_sensitive_data(item, parent_key=key_s)
        return redacted

    if isinstance(value, list):
        if _SENSITIVE_KEY_RE.search(parent_key):
            return "[REDACTED]"
        return [_redact_sensitive_data(item, parent_key=parent_key) for item in value]

    if isinstance(value, str):
        if _SENSITIVE_KEY_RE.search(parent_key):
            return "[REDACTED]"
        if parent_key == "generated_script" and _PRIVATE_KEY_VALUE_RE.search(value):
            return "[REDACTED: key-bearing generated script]"
        return _PRIVATE_KEY_VALUE_RE.sub("[REDACTED_PRIVATE_KEY]", value)

    return value


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


def assert_host_allowed(
    host: str,
    *,
    port: int | None = None,
    allowed_networks: Iterable[str] | None = None,
) -> None:
    """Allow only hosts whose resolved address is present in the network policy."""
    if not host:
        raise SecurityPolicyError("missing host")

    allowed = list(allowed_networks) if allowed_networks is not None else _load_allowed_networks()
    if not allowed:
        return

    host = str(host).lower().rstrip(".")
    if _host_matches_allowed(host, allowed):
        return

    try:
        resolved_ips = {
            ipaddress.ip_address(result[4][0])
            for result in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        }
    except Exception as exc:
        raise SecurityPolicyError(f"could not resolve host {host!r}: {exc}") from exc

    if any(_ip_matches_allowed(ip, allowed) for ip in resolved_ips):
        return

    raise SecurityPolicyError(
        f"host {host!r} is not in allowed networks. "
        "Set CTF_AGENTS_ALLOWED_NETWORKS for authorized spawned targets."
    )


def networks_from_challenge(challenge: dict) -> List[str]:
    """Extract only loopback/local spawned hosts from a parsed challenge object.

    Challenge metadata is untrusted and must not authorize arbitrary outbound
    network access. Remote targets require explicit operator approval through
    config/system_config.yaml or CTF_AGENTS_ALLOWED_NETWORKS.
    """
    candidates: List[str] = []
    for key in ("url", "rpc_url", "rpcUrl", "flag_url", "flagUrl"):
        value = challenge.get(key)
        if value:
            candidates.append(str(value))

    target = challenge.get("target")
    if isinstance(target, dict):
        candidates.extend(str(value) for value in target.values() if value)
    elif target:
        candidates.append(str(target))

    connection_info = challenge.get("connection_info")
    if isinstance(connection_info, dict):
        candidates.extend(str(value) for value in connection_info.values() if value)

    networks: List[str] = []
    for value in candidates:
        host = _host_from_urlish(value)
        if host and _is_loopback_host(host) and host not in networks:
            networks.append(host)
    return networks


@contextmanager
def temporary_allowed_networks(networks: Iterable[str]) -> Iterator[None]:
    """Temporarily extend CTF_AGENTS_ALLOWED_NETWORKS for one solve."""
    additions = [str(item).strip() for item in networks if str(item).strip()]
    if not additions:
        yield
        return

    previous = os.environ.get("CTF_AGENTS_ALLOWED_NETWORKS")
    existing = [item for item in (previous or "").split(",") if item]
    combined = existing[:]
    for item in additions:
        if item not in combined:
            combined.append(item)
    os.environ["CTF_AGENTS_ALLOWED_NETWORKS"] = ",".join(combined)
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("CTF_AGENTS_ALLOWED_NETWORKS", None)
        else:
            os.environ["CTF_AGENTS_ALLOWED_NETWORKS"] = previous


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


def _is_loopback_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _host_from_urlish(value: str) -> str | None:
    parsed = urlparse(value if re.match(r"^\w+://", value) else f"http://{value}")
    if parsed.hostname:
        return parsed.hostname.lower().rstrip(".")
    return None

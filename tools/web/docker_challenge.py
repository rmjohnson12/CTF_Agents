from __future__ import annotations

import hashlib
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import requests

from tools.common.result import ToolResult
from tools.common.runner import ToolRunner


@dataclass(frozen=True)
class DockerLaunchResult:
    context_dir: str
    image_tag: str
    container_id: str
    container_port: int
    host_port: int
    url: str
    build: ToolResult
    run: ToolResult
    logs_tail: str


class DockerChallengeTool:
    """
    Opt-in runner for local Docker-based CTF web challenges.

    The tool only executes Docker when CTF_AGENTS_ALLOW_DOCKER=1 is set. It
    binds containers to 127.0.0.1 and labels them for later cleanup.
    """

    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    def find_context(self, paths: List[str]) -> Optional[Path]:
        for raw_path in paths:
            path = Path(raw_path).expanduser().resolve()
            candidates = [path] if path.is_dir() else [path.parent]
            if path.is_dir():
                candidates.extend(parent for parent in path.rglob("*") if parent.is_dir())

            for candidate in candidates:
                if (candidate / "Dockerfile").exists():
                    return candidate
        return None

    def launch(self, context_dir: str, *, timeout_s: int = 300) -> DockerLaunchResult:
        if os.getenv("CTF_AGENTS_ALLOW_DOCKER") != "1":
            raise PermissionError("Docker execution is disabled. Set CTF_AGENTS_ALLOW_DOCKER=1 to allow local container runs.")

        context = Path(context_dir).expanduser().resolve()
        if not (context / "Dockerfile").exists():
            raise FileNotFoundError(f"No Dockerfile found in {context}")

        container_port = self._infer_container_port(context / "Dockerfile")
        digest = hashlib.sha1(str(context).encode("utf-8")).hexdigest()[:10]
        image_tag = f"ctf-agents-local-{digest}"

        build = self.runner.run(["docker", "build", "-t", image_tag, str(context)], timeout_s=timeout_s)
        if build.exit_code != 0:
            raise RuntimeError(f"docker build failed: {build.stderr or build.stdout}")

        run = self.runner.run(
            [
                "docker",
                "run",
                "-d",
                "--label",
                "ctf-agents.local-challenge=true",
                "-p",
                f"127.0.0.1::{container_port}",
                image_tag,
            ],
            timeout_s=60,
        )
        if run.exit_code != 0:
            raise RuntimeError(f"docker run failed: {run.stderr or run.stdout}")

        container_id = run.stdout.strip()
        host_port = self._resolve_host_port(container_id, container_port)
        url = f"http://127.0.0.1:{host_port}"
        self._wait_for_http(url)
        logs_tail = self.logs_tail(container_id)

        return DockerLaunchResult(
            context_dir=str(context),
            image_tag=image_tag,
            container_id=container_id,
            container_port=container_port,
            host_port=host_port,
            url=url,
            build=build,
            run=run,
            logs_tail=logs_tail,
        )

    def cleanup(self, container_id: str) -> ToolResult:
        return self.runner.run(["docker", "rm", "-f", container_id], timeout_s=30)

    def logs_tail(self, container_id: str, *, lines: int = 40) -> str:
        result = self.runner.run(["docker", "logs", "--tail", str(lines), container_id], timeout_s=30)
        return (result.stdout + result.stderr).strip()

    def _resolve_host_port(self, container_id: str, container_port: int) -> int:
        result = self.runner.run(["docker", "port", container_id, f"{container_port}/tcp"], timeout_s=30)
        if result.exit_code != 0:
            raise RuntimeError(f"docker port failed: {result.stderr or result.stdout}")
        match = re.search(r"127\.0\.0\.1:(\d+)|0\.0\.0\.0:(\d+)|:::(\d+)", result.stdout)
        if not match:
            raise RuntimeError(f"Could not parse mapped host port from: {result.stdout}")
        return int(next(group for group in match.groups() if group))

    @staticmethod
    def _infer_container_port(dockerfile: Path) -> int:
        try:
            text = dockerfile.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return 3000
        expose = re.search(r"(?im)^\s*EXPOSE\s+(\d+)", text)
        if expose:
            return int(expose.group(1))
        if re.search(r"npm\s+run\s+dev|next\s+(?:start|dev)|yarn\s+(?:start|dev)", text, re.I):
            return 3000
        return 3000

    @staticmethod
    def _wait_for_http(url: str, *, timeout_s: int = 30) -> None:
        deadline = time.time() + timeout_s
        last_error: Optional[Exception] = None
        while time.time() < deadline:
            try:
                response = requests.get(url, timeout=2)
                if response.status_code < 500:
                    return
            except Exception as exc:
                last_error = exc
            time.sleep(1)
        raise TimeoutError(f"Container did not become ready at {url}: {last_error}")

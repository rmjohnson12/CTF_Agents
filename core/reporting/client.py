"""Configurable best-effort client used by coordinators and agents."""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
from typing import Any, Mapping, Optional, Protocol, Union
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from core.reporting.models import ProgressUpdate
from core.reporting.redaction import redact_reporting_data


logger = logging.getLogger(__name__)


class ProgressReporter(Protocol):
    def emit(self, update: Union[ProgressUpdate, Mapping[str, Any]]) -> bool:
        """Send one update without raising into the solve path."""


class HttpProgressReporter:
    """Small synchronous HTTP reporter; disabled unless an endpoint is configured."""

    def __init__(
        self,
        endpoint: str,
        *,
        token: Optional[str] = None,
        timeout_seconds: float = 2.0,
        include_final_flag: bool = False,
        background: bool = False,
    ) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("reporting endpoint must be an http(s) URL")
        normalized = endpoint.rstrip("/")
        self.endpoint = normalized if normalized.endswith("/api/v1/updates") else (
            normalized + "/api/v1/updates"
        )
        self.token = token
        self.timeout_seconds = max(0.1, float(timeout_seconds))
        self.include_final_flag = include_final_flag
        self.background = background
        self._queue: queue.Queue = queue.Queue(maxsize=1000)
        self._worker: Optional[threading.Thread] = None
        if background:
            self._worker = threading.Thread(
                target=self._run_worker,
                name="ctf-reporting",
                daemon=True,
            )
            self._worker.start()

    @classmethod
    def from_env(cls) -> Optional["HttpProgressReporter"]:
        endpoint = os.getenv("CTF_AGENTS_REPORTING_URL", "").strip()
        if not endpoint:
            return None
        try:
            timeout = float(os.getenv("CTF_AGENTS_REPORTING_TIMEOUT", "2"))
        except ValueError:
            timeout = 2.0
        return cls(
            endpoint,
            token=(
                os.getenv("CTF_AGENTS_REPORTING_WRITE_TOKEN")
                or os.getenv("CTF_AGENTS_REPORTING_TOKEN")
                or None
            ),
            timeout_seconds=timeout,
            include_final_flag=os.getenv("CTF_AGENTS_REPORT_FINAL_FLAG") == "1",
            background=True,
        )

    def emit(self, update: Union[ProgressUpdate, Mapping[str, Any]]) -> bool:
        try:
            event = update if isinstance(update, ProgressUpdate) else ProgressUpdate.model_validate(update)
            payload = redact_reporting_data(event.model_dump(mode="json"), include_flags=False)
            if event.final_flag:
                payload["final_flag"] = event.final_flag if self.include_final_flag else "[REDACTED]"
            if self.background:
                self._queue.put_nowait(payload)
                return True
            return self._send_payload(payload)
        except queue.Full:
            logger.warning("Live reporting queue is full; dropping update")
            return False
        except (ValueError, TypeError) as exc:
            logger.warning("Live reporting update failed: %s", exc)
            return False

    def _send_payload(self, payload: Mapping[str, Any]) -> bool:
        try:
            body = json.dumps(payload).encode("utf-8")
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            request = Request(self.endpoint, data=body, headers=headers, method="POST")
            with urlopen(request, timeout=self.timeout_seconds) as response:
                return 200 <= int(response.status) < 300
        except (HTTPError, URLError, OSError, ValueError, TypeError) as exc:
            logger.warning("Live reporting update failed: %s", exc)
            return False

    def _run_worker(self) -> None:
        while True:
            payload = self._queue.get()
            try:
                self._send_payload(payload)
            finally:
                self._queue.task_done()

    def flush(self, timeout_seconds: float = 1.0) -> bool:
        """Wait briefly for queued events without holding up normal solve steps."""
        if not self.background:
            return True
        deadline = time.monotonic() + max(0.0, timeout_seconds)
        while self._queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.01)
        return self._queue.unfinished_tasks == 0

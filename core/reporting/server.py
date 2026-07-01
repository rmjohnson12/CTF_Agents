"""aiohttp API for durable solve timelines and Server-Sent Events."""

from __future__ import annotations

import asyncio
import hmac
import json
import os
import sqlite3
from collections import defaultdict
from typing import DefaultDict, Optional, Set

from aiohttp import web
from pydantic import ValidationError

from core.reporting.models import ProgressUpdate
from core.reporting.store import DEFAULT_REPORTING_DB, ReportingStore
from core.reporting.redaction import redact_reporting_data


class EventStreamBroker:
    """Fan out newly persisted events to SSE clients in this server process."""

    def __init__(self) -> None:
        self._subscribers: DefaultDict[str, Set[asyncio.Queue]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def subscribe(self, run_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=256)
        async with self._lock:
            self._subscribers[run_id].add(queue)
        return queue

    async def unsubscribe(self, run_id: str, queue: asyncio.Queue) -> None:
        async with self._lock:
            subscribers = self._subscribers.get(run_id)
            if subscribers is None:
                return
            subscribers.discard(queue)
            if not subscribers:
                self._subscribers.pop(run_id, None)

    async def publish(self, run_id: str, event: dict) -> None:
        async with self._lock:
            queues = list(self._subscribers.get(run_id, ()))
        for queue in queues:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # Slow clients can reconnect with Last-Event-ID to recover from SQLite.
                pass


def _bearer_token(request: web.Request) -> str:
    value = request.headers.get("Authorization", "")
    prefix = "Bearer "
    return value[len(prefix):].strip() if value.startswith(prefix) else ""


def _authorized(request: web.Request, configured_token: Optional[str]) -> bool:
    if not configured_token:
        return True
    supplied = _bearer_token(request)
    return bool(supplied) and hmac.compare_digest(supplied, configured_token)


def create_app(
    *,
    store: Optional[ReportingStore] = None,
    api_token: Optional[str] = None,
    write_token: Optional[str] = None,
    read_token: Optional[str] = None,
    public_read: Optional[bool] = None,
    allowed_origins: Optional[Set[str]] = None,
    store_final_flags: bool = False,
) -> web.Application:
    """Create the reporting API without starting a process or opening a port."""
    reporting_store = store or ReportingStore(
        os.getenv("CTF_AGENTS_REPORTING_DB", DEFAULT_REPORTING_DB)
    )
    fallback_token = api_token if api_token is not None else os.getenv("CTF_AGENTS_REPORTING_API_TOKEN")
    write_token = write_token or os.getenv("CTF_AGENTS_REPORTING_WRITE_TOKEN") or fallback_token
    read_token = (
        read_token
        or os.getenv("CTF_AGENTS_REPORTING_READ_TOKEN")
        or fallback_token
        or write_token
    )
    if public_read is None:
        public_read = os.getenv("CTF_AGENTS_REPORTING_PUBLIC_READ") == "1"
    origins = allowed_origins
    if origins is None:
        origins = {
            item.strip().rstrip("/")
            for item in os.getenv("CTF_AGENTS_REPORTING_ALLOWED_ORIGINS", "").split(",")
            if item.strip()
        }
    stream_broker = EventStreamBroker()

    @web.middleware
    async def security_middleware(request: web.Request, handler):
        origin = request.headers.get("Origin")
        if origin and origin.rstrip("/") not in origins:
            return web.json_response({"error": "origin_not_allowed"}, status=403)
        if request.method == "OPTIONS":
            response = web.Response(status=204)
        else:
            required_token = None
            if request.path != "/health":
                required_token = write_token if request.method == "POST" else (
                    None if public_read else read_token
                )
            if required_token and not _authorized(request, required_token):
                response = web.json_response({"error": "unauthorized"}, status=401)
            else:
                response = await handler(request)
        if origin and origin.rstrip("/") in origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
            response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, Last-Event-ID"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return response

    app = web.Application(client_max_size=1024 * 1024, middlewares=[security_middleware])

    async def health(_request: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    async def submit_update(request: web.Request) -> web.Response:
        try:
            raw = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return web.json_response({"error": "invalid_json"}, status=400)
        if not isinstance(raw, dict):
            return web.json_response({"error": "json_object_required"}, status=400)
        try:
            event = ProgressUpdate.model_validate(raw)
        except ValidationError as exc:
            return web.json_response(
                {"error": "validation_error", "details": json.loads(exc.json(include_url=False))},
                status=422,
            )

        safe_event = redact_reporting_data(
            event.model_dump(mode="python"),
            include_flags=False,
        )
        sanitized = event.model_copy(
            update={
                "step_description": safe_event["step_description"],
                "artifacts": safe_event["artifacts"],
                "error_message": safe_event["error_message"],
                "final_flag": event.final_flag if store_final_flags else (
                    "[REDACTED]" if event.final_flag else None
                ),
            }
        )
        try:
            row_id = reporting_store.append(sanitized)
        except sqlite3.IntegrityError as exc:
            if "progress_updates.event_id" in str(exc):
                return web.json_response({"error": "duplicate_event_id"}, status=409)
            raise
        stored = reporting_store.timeline(sanitized.run_id, after_id=row_id - 1, limit=1)[0]
        await stream_broker.publish(sanitized.run_id, stored)
        return web.json_response({"id": row_id, "event": stored}, status=201)

    async def get_timeline(request: web.Request) -> web.Response:
        run_id = request.match_info["run_id"]
        try:
            after_id = int(request.query.get("after_id", "0"))
            limit = int(request.query.get("limit", "2000"))
        except ValueError:
            return web.json_response({"error": "invalid_pagination"}, status=400)
        updates = reporting_store.timeline(run_id, after_id=after_id, limit=limit)
        return web.json_response({"run_id": run_id, "count": len(updates), "updates": updates})

    async def stream_timeline(request: web.Request) -> web.StreamResponse:
        run_id = request.match_info["run_id"]
        try:
            after_id = int(
                request.headers.get("Last-Event-ID")
                or request.query.get("after_id", "0")
            )
        except ValueError:
            raise web.HTTPBadRequest(text="invalid Last-Event-ID")

        stream_headers = {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
        origin = request.headers.get("Origin")
        if origin and origin.rstrip("/") in origins:
            stream_headers["Access-Control-Allow-Origin"] = origin
            stream_headers["Vary"] = "Origin"
        response = web.StreamResponse(
            status=200,
            headers=stream_headers,
        )
        await response.prepare(request)
        queue = await stream_broker.subscribe(run_id)
        sent_ids = set()
        try:
            for event in reporting_store.timeline(run_id, after_id=after_id):
                sent_ids.add(event["id"])
                await _write_sse(response, event)
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                    if event["id"] not in sent_ids:
                        sent_ids.add(event["id"])
                        await _write_sse(response, event)
                except asyncio.TimeoutError:
                    await response.write(b": heartbeat\n\n")
        except (ConnectionResetError, asyncio.CancelledError):
            pass
        finally:
            await stream_broker.unsubscribe(run_id, queue)
        return response

    app.router.add_get("/health", health)
    app.router.add_post("/api/v1/updates", submit_update)
    app.router.add_get("/api/v1/runs/{run_id}/timeline", get_timeline)
    app.router.add_get("/api/v1/runs/{run_id}/stream", stream_timeline)
    return app


async def _write_sse(response: web.StreamResponse, event: dict) -> None:
    payload = json.dumps(event, separators=(",", ":"))
    await response.write(
        f"id: {event['id']}\nevent: progress\ndata: {payload}\n\n".encode("utf-8")
    )

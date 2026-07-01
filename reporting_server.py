"""Run the optional live-reporting HTTP/SSE service."""

from __future__ import annotations

import argparse
import os

from aiohttp import web

from core.reporting.server import create_app
from core.reporting.store import ReportingStore


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve durable CTF agent progress timelines.")
    parser.add_argument("--host", default=os.getenv("CTF_AGENTS_REPORTING_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("CTF_AGENTS_REPORTING_PORT", "8787")))
    parser.add_argument("--db", default=os.getenv("CTF_AGENTS_REPORTING_DB", "logs/reporting.db"))
    args = parser.parse_args()

    token = (
        os.getenv("CTF_AGENTS_REPORTING_WRITE_TOKEN")
        or os.getenv("CTF_AGENTS_REPORTING_API_TOKEN")
    )
    if args.host not in {"127.0.0.1", "localhost", "::1"} and not token:
        parser.error("CTF_AGENTS_REPORTING_WRITE_TOKEN is required for a non-loopback bind")

    app = create_app(
        store=ReportingStore(args.db),
        write_token=token,
        store_final_flags=os.getenv("CTF_AGENTS_REPORTING_STORE_FLAGS") == "1",
    )
    web.run_app(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()

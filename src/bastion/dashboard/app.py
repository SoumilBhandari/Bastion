"""A local web dashboard that visualizes the Bastion audit log."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

from bastion.audit import read_records
from bastion.config.schema import BastionConfig

_INDEX_HTML = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")


def _summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute headline stats over all audit records."""
    ok = sum(1 for r in records if r.get("outcome") == "ok")
    denied = sum(1 for r in records if r.get("outcome") == "denied")
    errors = sum(1 for r in records if r.get("outcome") == "error")
    total_ms = sum(float(r.get("duration_ms") or 0.0) for r in records)
    return {
        "total": len(records),
        "ok": ok,
        "denied": denied,
        "errors": errors,
        "total_ms": round(total_ms, 1),
    }


def build_dashboard_app(config: BastionConfig) -> Starlette:
    """Build the Starlette app that serves the audit-log dashboard."""
    audit_path = config.audit.path

    async def index(request: Request) -> HTMLResponse:
        return HTMLResponse(_INDEX_HTML)

    async def api_audit(request: Request) -> JSONResponse:
        records = read_records(audit_path)
        recent = list(reversed(records))[:500]
        return JSONResponse({"records": recent, "summary": _summarize(records)})

    return Starlette(routes=[Route("/", index), Route("/api/audit", api_audit)])


def run_dashboard(config: BastionConfig, host: str, port: int) -> None:
    """Serve the audit-log dashboard (blocking)."""
    uvicorn.run(build_dashboard_app(config), host=host, port=port, log_level="warning")

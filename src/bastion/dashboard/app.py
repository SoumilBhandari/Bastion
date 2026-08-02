"""A local web dashboard that visualizes the Bastion audit log."""

from __future__ import annotations

import secrets
from collections import Counter
from pathlib import Path
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from bastion.audit.chain import verify_records
from bastion.audit.reader import IncrementalLog
from bastion.config.schema import BastionConfig

_INDEX_HTML = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")

RECENT_LIMIT = 500
TOP_TOOLS = 8


def new_token() -> str:
    """A fresh access token for one dashboard session."""
    return secrets.token_urlsafe(16)


def _number(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute headline stats over all audit records."""
    outcomes: Counter[str] = Counter(str(r.get("outcome", "")) for r in records)
    tools: Counter[str] = Counter(str(r.get("tool", "")) for r in records)
    flags: Counter[str] = Counter(str(flag) for r in records for flag in (r.get("flags") or []))
    return {
        "total": len(records),
        "ok": outcomes.get("ok", 0),
        "denied": outcomes.get("denied", 0),
        "errors": outcomes.get("error", 0),
        "flagged": sum(1 for r in records if r.get("flags")),
        "total_ms": round(sum(_number(r.get("duration_ms")) for r in records), 1),
        "spend": round(sum(_number(r.get("cost")) for r in records), 6),
        "top_tools": [{"name": n, "calls": c} for n, c in tools.most_common(TOP_TOOLS)],
        "top_flags": [{"name": n, "count": c} for n, c in flags.most_common(5)],
    }


def build_dashboard_app(config: BastionConfig, *, token: str | None = None) -> Starlette:
    """Build the Starlette app that serves the audit-log dashboard.

    The dashboard serves the raw audit log, arguments included, so it is gated
    on a per-session token. Without one, anything else running on the machine —
    or a page that guesses the port — could read the whole record of what your
    agent did simply by knowing the address. Pass ``token=None`` only when
    something else is doing the authenticating.
    """
    log = IncrementalLog(config.audit.path)

    def authorized(request: Request) -> bool:
        if token is None:
            return True
        supplied = request.query_params.get("t") or request.headers.get("x-bastion-token", "")
        return secrets.compare_digest(supplied, token)

    async def index(request: Request) -> Response:
        if not authorized(request):
            return HTMLResponse(_UNAUTHORIZED_HTML, status_code=401)
        return HTMLResponse(_INDEX_HTML)

    async def api_audit(request: Request) -> Response:
        if not authorized(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        records = log.records()
        chain = verify_records(records)
        return JSONResponse(
            {
                "records": list(reversed(records))[:RECENT_LIMIT],
                "summary": _summarize(records),
                "chain": {
                    "ok": chain.ok,
                    "checked": chain.checked,
                    "unchained": chain.unchained,
                    "problem": str(chain.breaks[0]) if chain.breaks else None,
                },
            }
        )

    return Starlette(routes=[Route("/", index), Route("/api/audit", api_audit)])


_UNAUTHORIZED_HTML = (
    "<h1>401</h1><p>This dashboard needs its access token. Open the URL that "
    "<code>bastion dashboard</code> printed when it started.</p>"
)


def run_dashboard(
    config: BastionConfig,
    host: str,
    port: int,
    *,
    token: str | None = None,
) -> None:
    """Serve the audit-log dashboard (blocking)."""
    uvicorn.run(
        build_dashboard_app(config, token=token),
        host=host,
        port=port,
        log_level="warning",
    )

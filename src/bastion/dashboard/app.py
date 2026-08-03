"""A local web dashboard that visualizes the Bastion audit log."""

from __future__ import annotations

import secrets
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from bastion.audit.chain import ChainReport, verify_records
from bastion.audit.reader import IncrementalLog, read_records
from bastion.audit.record import json_safe
from bastion.config.schema import BastionConfig

_INDEX_HTML = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")

RECENT_LIMIT = 500
TOP_TOOLS = 8

VERIFY_INTERVAL_SECONDS = 5.0
"""How often the whole chain is re-checked, however fast the page polls.

Detecting an edit to an already-seen record means reading the file again, so
this is the trade: a poll costs nothing most of the time, and tampering is
reported within this many seconds rather than never. `bastion verify` remains
the authoritative check and always reads everything."""


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


class _LiveLog:
    """The dashboard's view of a growing log, kept up to date incrementally.

    The page polls every 1.5 seconds. Re-reading and re-summarising the whole
    file each time makes watching a log cost more the longer it gets — on an
    append-only file, forever. Records are read from where the last poll
    stopped and the totals accumulate rather than being recomputed.

    Chain verification deliberately does *not* work that way. Verifying only
    what is new is faster still, but it never looks at a record twice, so
    editing one the dashboard had already checked went unnoticed and the page
    kept reporting an intact chain for a log `bastion verify` rejects — the
    one thing the banner exists to catch. Verification re-reads the whole file,
    throttled to :data:`VERIFY_INTERVAL_SECONDS` so a fast poll cannot pin a
    core, which bounds how long tampering can go unreported rather than
    allowing it indefinitely.
    """

    def __init__(self, log: IncrementalLog, *, now: Callable[[], float] = time.monotonic) -> None:
        self._log = log
        self._now = now
        self._chain = ChainReport()
        self._verified_at: float | None = None
        self._reset()

    def _reset(self) -> None:
        self._counts: Counter[str] = Counter()
        self._tools: Counter[str] = Counter()
        self._flags: Counter[str] = Counter()
        self._total_ms = 0.0
        self._spend = 0.0
        self._flagged = 0
        self._total = 0

    def snapshot(self) -> dict[str, Any]:
        self._take_in(self._log.new_records())
        chain = self._verify()
        return {
            "records": list(reversed(self._log.records()))[:RECENT_LIMIT],
            "summary": {
                "total": self._total,
                "ok": self._counts.get("ok", 0),
                "denied": self._counts.get("denied", 0),
                "errors": self._counts.get("error", 0),
                "cancelled": self._counts.get("cancelled", 0),
                "flagged": self._flagged,
                "total_ms": round(self._total_ms, 1),
                "spend": round(self._spend, 6),
                "top_tools": [
                    {"name": n, "calls": c} for n, c in self._tools.most_common(TOP_TOOLS)
                ],
                "top_flags": [{"name": n, "count": c} for n, c in self._flags.most_common(5)],
            },
            "chain": {
                "ok": chain.ok,
                "checked": chain.checked,
                "unchained": chain.unchained,
                "problem": str(chain.breaks[0]) if chain.breaks else None,
            },
        }

    def _verify(self) -> ChainReport:
        """Re-verify the whole log, at most once every VERIFY_INTERVAL_SECONDS.

        Re-read from disk rather than checked against the records held in
        memory: an in-place edit does not change the file's length, so the
        incremental reader would never see it and the cached copy would still
        look intact.
        """
        now = self._now()
        if self._verified_at is not None and now - self._verified_at < VERIFY_INTERVAL_SECONDS:
            return self._chain
        self._chain = verify_records(read_records(self._log.path))
        self._verified_at = now
        return self._chain

    def _take_in(self, fresh: list[dict[str, Any]]) -> None:
        if len(self._log.records()) < self._total:
            # Rotated or truncated: the totals accumulated so far describe a
            # file that no longer exists, so start the whole view again.
            self._reset()
            fresh = self._log.records()
        for record in fresh:
            self._total += 1
            self._counts[str(record.get("outcome", ""))] += 1
            self._tools[str(record.get("tool", ""))] += 1
            self._total_ms += _number(record.get("duration_ms"))
            self._spend += _number(record.get("cost"))
            if flags := record.get("flags"):
                self._flagged += 1
                for flag in flags:
                    self._flags[str(flag)] += 1


def build_dashboard_app(
    config: BastionConfig,
    *,
    token: str | None = None,
    now: Callable[[], float] = time.monotonic,
) -> Starlette:
    """Build the Starlette app that serves the audit-log dashboard.

    The dashboard serves the raw audit log, arguments included, so it is gated
    on a per-session token. Without one, anything else running on the machine —
    or a page that guesses the port — could read the whole record of what your
    agent did simply by knowing the address. Pass ``token=None`` only when
    something else is doing the authenticating.
    """
    log = IncrementalLog(config.audit.path)
    state = _LiveLog(log, now=now)

    def authorized(request: Request) -> bool:
        if token is None:
            return True
        supplied = request.query_params.get("t") or request.headers.get("x-bastion-token", "")
        # compare_digest rejects non-ASCII str outright; compare bytes so a
        # token full of emoji is refused as wrong rather than raising a 500.
        return secrets.compare_digest(supplied.encode("utf-8"), token.encode("utf-8"))

    async def index(request: Request) -> Response:
        if not authorized(request):
            return HTMLResponse(_UNAUTHORIZED_HTML, status_code=401)
        return HTMLResponse(_INDEX_HTML)

    async def api_audit(request: Request) -> Response:
        if not authorized(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        # Sanitised here rather than on the way in: a log written before
        # non-finite values were caught still contains bare `Infinity`, and its
        # hashes were computed over that, so rewriting it as it is read would
        # report tampering that never happened. Only what is served needs to be
        # JSON a browser can parse.
        return JSONResponse(json_safe(state.snapshot()))

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

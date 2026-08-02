"""A per-request channel for findings that surface below the audit middleware.

Response inspection happens inside the middleware chain, but its findings
belong in the audit record written outside it. A context variable carries them
across that gap: it is per-task under asyncio, so concurrent calls through the
same gateway cannot see each other's flags.
"""

from __future__ import annotations

from contextvars import ContextVar, Token

_FLAGS: ContextVar[list[str] | None] = ContextVar("bastion_response_flags", default=None)


def begin() -> Token[list[str] | None]:
    """Start collecting flags for one request. Pass the token back to :func:`end`."""
    return _FLAGS.set([])


def end(token: Token[list[str] | None]) -> list[str]:
    """Finish collecting and return whatever was recorded."""
    collected = _FLAGS.get() or []
    _FLAGS.reset(token)
    return list(collected)


def record(flags: list[str]) -> None:
    """Add flags to the request in progress; a no-op outside one."""
    current = _FLAGS.get()
    if current is not None:
        current.extend(flags)

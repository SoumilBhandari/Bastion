"""A per-request channel for findings that surface below the audit middleware.

Some of what belongs in an audit record is only known deeper in the middleware
chain than the layer that writes it: what a response guard found, what a call
actually cost. A context variable carries those back up. It is per-task under
asyncio, so concurrent calls through the same gateway cannot see each other's
notes.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass, field


@dataclass
class RequestNotes:
    """What the inner middleware learned about one request."""

    flags: list[str] = field(default_factory=list)
    cost: float | None = None


_NOTES: ContextVar[RequestNotes | None] = ContextVar("bastion_request_notes", default=None)


def begin() -> Token[RequestNotes | None]:
    """Start collecting notes for one request. Pass the token back to :func:`end`."""
    return _NOTES.set(RequestNotes())


def end(token: Token[RequestNotes | None]) -> RequestNotes:
    """Finish collecting and return whatever was recorded."""
    collected = _NOTES.get() or RequestNotes()
    _NOTES.reset(token)
    return collected


def add_flags(flags: list[str]) -> None:
    """Add findings to the request in progress; a no-op outside one."""
    if (current := _NOTES.get()) is not None:
        current.flags.extend(flags)


def set_cost(cost: float) -> None:
    """Record what the request in progress was actually charged."""
    if (current := _NOTES.get()) is not None:
        current.cost = cost

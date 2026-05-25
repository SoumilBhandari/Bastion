"""Middleware that records every tool call to the audit log."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp.types import CallToolRequestParams

from bastion.audit.record import AuditRecord
from bastion.audit.writer import AuditWriter
from bastion.policy.models import PolicyDenied

RedactFn = Callable[[str, dict[str, Any]], dict[str, Any]]


class AuditMiddleware(Middleware):
    """Writes one audit record for every ``tools/call`` through the gateway.

    When ``redact_fn`` is provided, it is applied to the arguments before they
    are written to the audit log — used by the guard engine to keep secrets
    out of audited records without changing what the upstream actually sees.
    """

    def __init__(
        self,
        writer: AuditWriter,
        *,
        log_arguments: bool = True,
        redact_fn: RedactFn | None = None,
    ) -> None:
        super().__init__()
        self._writer = writer
        self._log_arguments = log_arguments
        self._redact_fn = redact_fn

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        message = context.message
        arguments = dict(message.arguments) if message.arguments else None
        if arguments is not None and self._redact_fn is not None:
            arguments = self._redact_fn(message.name, arguments)
        record = AuditRecord(
            tool=message.name,
            arguments=arguments if self._log_arguments else None,
        )
        start = time.monotonic()
        try:
            return await call_next(context)
        except PolicyDenied as exc:
            record.outcome = "denied"
            record.error = str(exc)
            raise
        except Exception as exc:
            record.outcome = "error"
            record.error = str(exc)
            raise
        finally:
            record.duration_ms = round((time.monotonic() - start) * 1000, 3)
            self._writer.write(record)

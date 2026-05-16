"""Middleware that records every tool call to the audit log."""

from __future__ import annotations

import time

from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp.types import CallToolRequestParams

from bastion.audit.record import AuditRecord
from bastion.audit.writer import AuditWriter


class AuditMiddleware(Middleware):
    """Writes one audit record for every ``tools/call`` through the gateway."""

    def __init__(self, writer: AuditWriter, *, log_arguments: bool = True) -> None:
        super().__init__()
        self._writer = writer
        self._log_arguments = log_arguments

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        message = context.message
        arguments = dict(message.arguments) if message.arguments else None
        record = AuditRecord(
            tool=message.name,
            arguments=arguments if self._log_arguments else None,
        )
        start = time.monotonic()
        try:
            return await call_next(context)
        except Exception as exc:
            record.outcome = "error"
            record.error = str(exc)
            raise
        finally:
            record.duration_ms = round((time.monotonic() - start) * 1000, 3)
            self._writer.write(record)

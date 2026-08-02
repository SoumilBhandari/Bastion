"""Middleware that records every governed operation to the audit log."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any, TypeVar

from fastmcp.prompts.base import PromptResult
from fastmcp.resources.base import ResourceResult
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp.types import (
    CallToolRequestParams,
    GetPromptRequestParams,
    ReadResourceRequestParams,
)

from bastion.audit.record import AuditRecord
from bastion.audit.writer import AuditWriter
from bastion.policy import flags
from bastion.policy.models import PolicyDenied
from bastion.policy.secrets import redact_structure

RedactFn = Callable[[str, dict[str, Any]], dict[str, Any]]
_R = TypeVar("_R")

_MAX_ERROR_CHARS = 2000


def _result_error(result: Any) -> str | None:
    """Extract the error message from a failed result, or ``None`` if it succeeded.

    An upstream tool that raises does not propagate an exception through the
    proxy: FastMCP marshals the failure into a ``ToolResult`` with
    ``is_error=True`` and the message in its content. Without this check a
    failed call would be audited as ``ok``.
    """
    if not getattr(result, "is_error", False):
        return None
    texts = [
        text
        for block in getattr(result, "content", None) or []
        if isinstance(text := getattr(block, "text", None), str)
    ]
    message = "\n".join(texts).strip()
    return message[:_MAX_ERROR_CHARS] if message else "upstream reported an error"


class AuditMiddleware(Middleware):
    """Writes one audit record for every tool call, resource read, and prompt fetch.

    Arguments are redacted before they are written, so neither built-in secret
    detection nor a guard ``redact`` rule changes what the upstream actually
    receives — only what is committed to disk. Built-in detection runs first,
    then ``redact_fn`` for the operator's own rules.
    """

    def __init__(
        self,
        writer: AuditWriter,
        *,
        log_arguments: bool = True,
        redact_fn: RedactFn | None = None,
        redact_secrets: bool = True,
    ) -> None:
        super().__init__()
        self._writer = writer
        self._log_arguments = log_arguments
        self._redact_fn = redact_fn
        self._redact_secrets = redact_secrets

    def _arguments(self, name: str, raw: Any) -> dict[str, Any] | None:
        if not raw:
            return None
        arguments: dict[str, Any] = dict(raw)
        if self._redact_secrets:
            arguments = redact_structure(arguments)
        if self._redact_fn is not None:
            arguments = self._redact_fn(name, arguments)
        return arguments

    async def _record(
        self,
        *,
        kind: str,
        name: str,
        arguments: dict[str, Any] | None,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, _R],
    ) -> _R:
        record = AuditRecord(
            tool=name,
            kind=kind,
            arguments=arguments if self._log_arguments else None,
        )
        start = time.monotonic()
        token = flags.begin()
        try:
            result = await call_next(context)
        except PolicyDenied as exc:
            record.outcome = "denied"
            record.error = str(exc)
            raise
        except Exception as exc:
            record.outcome = "error"
            record.error = str(exc)
            raise
        else:
            if (message := _result_error(result)) is not None:
                record.outcome = "error"
                record.error = message
            return result
        finally:
            record.duration_ms = round((time.monotonic() - start) * 1000, 3)
            record.flags = flags.end(token) or None
            self._writer.write(record)

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        message = context.message
        return await self._record(
            kind="tool",
            name=message.name,
            arguments=self._arguments(message.name, message.arguments),
            context=context,
            call_next=call_next,
        )

    async def on_read_resource(
        self,
        context: MiddlewareContext[ReadResourceRequestParams],
        call_next: CallNext[ReadResourceRequestParams, ResourceResult],
    ) -> ResourceResult:
        return await self._record(
            kind="resource",
            name=str(context.message.uri),
            arguments=None,
            context=context,
            call_next=call_next,
        )

    async def on_get_prompt(
        self,
        context: MiddlewareContext[GetPromptRequestParams],
        call_next: CallNext[GetPromptRequestParams, PromptResult],
    ) -> PromptResult:
        message = context.message
        return await self._record(
            kind="prompt",
            name=message.name,
            arguments=self._arguments(message.name, message.arguments),
            context=context,
            call_next=call_next,
        )

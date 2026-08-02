"""Middleware that turns unexpected gateway errors into clean ToolErrors."""

from __future__ import annotations

from typing import TypeVar

from fastmcp.exceptions import ToolError
from fastmcp.prompts.base import PromptResult
from fastmcp.resources.base import ResourceResult
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp.types import (
    CallToolRequestParams,
    GetPromptRequestParams,
    ReadResourceRequestParams,
)

_R = TypeVar("_R")


class ErrorBoundary(Middleware):
    """Outermost middleware — wraps unexpected exceptions in a clean ToolError.

    Errors raised by upstream servers are already ``ToolError`` and pass
    through unchanged; anything else becomes a single, clearly-attributed
    gateway error rather than leaking an internal traceback to the agent.

    This covers resource reads and prompt fetches as well as tool calls: they
    reach the same upstreams over the same transports and fail the same ways.
    """

    async def _guarded(
        self,
        *,
        context: MiddlewareContext[object],
        call_next: CallNext[object, _R],
    ) -> _R:
        try:
            return await call_next(context)
        except ToolError:
            raise
        except Exception as exc:
            raise ToolError(f"[bastion] internal gateway error: {exc}") from exc

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        return await self._guarded(
            context=context,  # type: ignore[arg-type]
            call_next=call_next,  # type: ignore[arg-type]
        )

    async def on_read_resource(
        self,
        context: MiddlewareContext[ReadResourceRequestParams],
        call_next: CallNext[ReadResourceRequestParams, ResourceResult],
    ) -> ResourceResult:
        return await self._guarded(
            context=context,  # type: ignore[arg-type]
            call_next=call_next,  # type: ignore[arg-type]
        )

    async def on_get_prompt(
        self,
        context: MiddlewareContext[GetPromptRequestParams],
        call_next: CallNext[GetPromptRequestParams, PromptResult],
    ) -> PromptResult:
        return await self._guarded(
            context=context,  # type: ignore[arg-type]
            call_next=call_next,  # type: ignore[arg-type]
        )

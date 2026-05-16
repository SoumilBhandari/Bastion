"""Middleware that turns unexpected gateway errors into clean ToolErrors."""

from __future__ import annotations

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp.types import CallToolRequestParams


class ErrorBoundary(Middleware):
    """Outermost middleware — wraps unexpected exceptions in a clean ToolError.

    Tool errors raised by upstream servers are already ``ToolError`` and pass
    through unchanged; anything else becomes a single, clearly-attributed
    gateway error rather than leaking an internal traceback to the agent.
    """

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        try:
            return await call_next(context)
        except ToolError:
            raise
        except Exception as exc:
            raise ToolError(f"[bastion] internal gateway error: {exc}") from exc

"""Middleware that enforces the policy engine's decision on every tool call."""

from __future__ import annotations

from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp.types import CallToolRequestParams

from bastion.policy.engine import PolicyEngine
from bastion.policy.models import PolicyDenied


class PolicyMiddleware(Middleware):
    """Checks each ``tools/call`` against policy and blocks denied calls.

    A denied call raises before ``call_next``, so the upstream server is never
    reached. The denial still flows through the audit middleware above it.
    """

    def __init__(self, engine: PolicyEngine) -> None:
        super().__init__()
        self._engine = engine

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        tool = context.message.name
        decision = self._engine.check(tool)
        if not decision.allowed:
            raise PolicyDenied(f"blocked by Bastion policy: {decision.reason}")
        self._engine.reserve(tool)
        return await call_next(context)

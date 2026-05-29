"""Middleware that enforces the policy engine's decision on every operation."""

from __future__ import annotations

from fastmcp.prompts.base import PromptResult
from fastmcp.resources.base import ResourceResult
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp.types import (
    CallToolRequestParams,
    GetPromptRequestParams,
    ReadResourceRequestParams,
)

from bastion.policy.engine import PolicyEngine
from bastion.policy.models import PolicyDenied


class PolicyMiddleware(Middleware):
    """Checks each operation against policy and blocks denied ones.

    Tool calls run the full policy (permissions, guards, rate limits, budgets).
    Resource reads and prompt fetches run the permission check, so a
    default-deny policy denies them too and they can be allow/deny-listed by
    URI or name. A denied operation raises before ``call_next``, so the upstream
    is never reached; the denial still flows through the audit middleware above.
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
        arguments = dict(context.message.arguments) if context.message.arguments else {}
        decision = self._engine.check(tool, arguments)
        if not decision.allowed:
            raise PolicyDenied(f"blocked by Bastion policy: {decision.reason}")
        self._engine.reserve(tool)
        return await call_next(context)

    async def on_read_resource(
        self,
        context: MiddlewareContext[ReadResourceRequestParams],
        call_next: CallNext[ReadResourceRequestParams, ResourceResult],
    ) -> ResourceResult:
        decision = self._engine.check_permission(str(context.message.uri))
        if not decision.allowed:
            raise PolicyDenied(f"blocked by Bastion policy: {decision.reason}")
        return await call_next(context)

    async def on_get_prompt(
        self,
        context: MiddlewareContext[GetPromptRequestParams],
        call_next: CallNext[GetPromptRequestParams, PromptResult],
    ) -> PromptResult:
        decision = self._engine.check_permission(context.message.name)
        if not decision.allowed:
            raise PolicyDenied(f"blocked by Bastion policy: {decision.reason}")
        return await call_next(context)

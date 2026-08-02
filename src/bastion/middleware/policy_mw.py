"""Middleware that enforces the policy engine's decision on every operation."""

from __future__ import annotations

from collections.abc import Sequence

from fastmcp.prompts import Prompt
from fastmcp.prompts.base import PromptResult
from fastmcp.resources import Resource, ResourceTemplate
from fastmcp.resources.base import ResourceResult
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import Tool, ToolResult
from mcp.types import (
    CallToolRequestParams,
    GetPromptRequestParams,
    ListPromptsRequest,
    ListResourcesRequest,
    ListResourceTemplatesRequest,
    ListToolsRequest,
    ReadResourceRequestParams,
)

from bastion.policy import notes
from bastion.policy.engine import PolicyEngine
from bastion.policy.models import PolicyDenied


class PolicyMiddleware(Middleware):
    """Checks each operation against policy and blocks denied ones.

    Tool calls run the full policy (permissions, guards, rate limits, budgets).
    Resource reads and prompt fetches run the permission check, so a
    default-deny policy denies them too and they can be allow/deny-listed by
    URI or name. A denied operation raises before ``call_next``, so the upstream
    is never reached; the denial still flows through the audit middleware above.

    Listings are filtered to what policy actually permits. An agent shown a
    tool it can never call will try it — wasting a turn, and often several as
    it reasons about the refusal. Hiding denied tools also keeps a
    default-deny allowlist from burning context on hundreds of unusable
    entries. Filtering is presentation only: the call-time check above is what
    enforces policy, and it still runs for a client that calls a hidden name
    directly.
    """

    def __init__(self, engine: PolicyEngine, *, hide_denied: bool = True) -> None:
        super().__init__()
        self._engine = engine
        self._hide_denied = hide_denied

    def _permits(self, subject: str) -> bool:
        return self._engine.check_permission(subject).allowed

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
        notes.set_cost(self._engine.reserve(tool))
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

    async def on_list_tools(
        self,
        context: MiddlewareContext[ListToolsRequest],
        call_next: CallNext[ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        tools = await call_next(context)
        if not self._hide_denied:
            return tools
        return [tool for tool in tools if self._permits(tool.name)]

    async def on_list_resources(
        self,
        context: MiddlewareContext[ListResourcesRequest],
        call_next: CallNext[ListResourcesRequest, Sequence[Resource]],
    ) -> Sequence[Resource]:
        resources = await call_next(context)
        if not self._hide_denied:
            return resources
        return [resource for resource in resources if self._permits(str(resource.uri))]

    async def on_list_resource_templates(
        self,
        context: MiddlewareContext[ListResourceTemplatesRequest],
        call_next: CallNext[ListResourceTemplatesRequest, Sequence[ResourceTemplate]],
    ) -> Sequence[ResourceTemplate]:
        templates = await call_next(context)
        if not self._hide_denied:
            return templates
        return [template for template in templates if self._permits(str(template.uri_template))]

    async def on_list_prompts(
        self,
        context: MiddlewareContext[ListPromptsRequest],
        call_next: CallNext[ListPromptsRequest, Sequence[Prompt]],
    ) -> Sequence[Prompt]:
        prompts = await call_next(context)
        if not self._hide_denied:
            return prompts
        return [prompt for prompt in prompts if self._permits(prompt.name)]

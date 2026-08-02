"""Middleware that bounds how long the gateway waits on an upstream."""

from __future__ import annotations

import asyncio
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

from bastion.config.schema import TimeoutConfig

_R = TypeVar("_R")


class TimeoutMiddleware(Middleware):
    """Fails an upstream call that takes longer than its configured limit.

    A wedged upstream would otherwise hang the agent forever: the request is
    accepted, no answer comes back, and there is no error for the agent to
    react to. Turning that into a prompt, attributable failure lets the agent
    recover — and gets the timeout into the audit log, where an upstream that
    stalls repeatedly becomes visible.

    Timing out cancels the in-flight request. A well-behaved upstream notices
    and unwinds; one that does not may keep working on a result nobody is
    waiting for. That is the cost of not hanging indefinitely.
    """

    def __init__(self, timeouts: TimeoutConfig) -> None:
        super().__init__()
        self._timeouts = timeouts

    async def _bounded(
        self,
        *,
        name: str,
        kind: str,
        context: MiddlewareContext[object],
        call_next: CallNext[object, _R],
    ) -> _R:
        limit = self._timeouts.for_tool(name)
        if limit is None:
            return await call_next(context)
        try:
            return await asyncio.wait_for(call_next(context), timeout=limit)
        except TimeoutError as exc:
            raise ToolError(
                f"[bastion] {kind} '{name}' timed out after {limit:g}s. "
                "Raise timeouts.default_seconds, or set timeouts.per_tool for this one."
            ) from exc

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        return await self._bounded(
            name=context.message.name,
            kind="tool",
            context=context,  # type: ignore[arg-type]
            call_next=call_next,  # type: ignore[arg-type]
        )

    async def on_read_resource(
        self,
        context: MiddlewareContext[ReadResourceRequestParams],
        call_next: CallNext[ReadResourceRequestParams, ResourceResult],
    ) -> ResourceResult:
        return await self._bounded(
            name=str(context.message.uri),
            kind="resource",
            context=context,  # type: ignore[arg-type]
            call_next=call_next,  # type: ignore[arg-type]
        )

    async def on_get_prompt(
        self,
        context: MiddlewareContext[GetPromptRequestParams],
        call_next: CallNext[GetPromptRequestParams, PromptResult],
    ) -> PromptResult:
        return await self._bounded(
            name=context.message.name,
            kind="prompt",
            context=context,  # type: ignore[arg-type]
            call_next=call_next,  # type: ignore[arg-type]
        )

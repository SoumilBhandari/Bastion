"""Middleware that watches for tool definitions changing under the agent."""

from __future__ import annotations

from collections.abc import Sequence

from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import Tool, ToolResult
from mcp.types import CallToolRequestParams, ListToolsRequest

from bastion.audit.record import AuditRecord
from bastion.audit.writer import AuditWriter
from bastion.policy.models import PolicyDenied
from bastion.policy.pinning import PinChecker, ToolFingerprint


class PinningMiddleware(Middleware):
    """Fingerprints tool definitions and reacts when they change.

    The check runs on ``tools/list``, which every client issues when it
    connects — that is the moment a changed description would reach the agent,
    and the only moment the gateway sees the definition at all. Under
    ``block``, drifted tools are dropped from the listing and added to a
    quarantine that the call path also refuses, so a client working from a
    listing it cached earlier still cannot reach them.
    """

    def __init__(
        self,
        checker: PinChecker,
        *,
        block_on_change: bool = False,
        writer: AuditWriter | None = None,
    ) -> None:
        super().__init__()
        self._checker = checker
        self._block = block_on_change
        self._writer = writer
        self._quarantined: set[str] = set()

    @property
    def quarantined(self) -> frozenset[str]:
        return frozenset(self._quarantined)

    async def on_list_tools(
        self,
        context: MiddlewareContext[ListToolsRequest],
        call_next: CallNext[ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        tools = await call_next(context)
        report = self._checker.check([ToolFingerprint.of(tool.to_mcp_tool()) for tool in tools])

        for drift in report.drifted:
            self._quarantined.add(drift.name)
            self._note(
                name=drift.name,
                message=drift.summary(),
                blocked=self._block,
            )

        if not self._block or not self._quarantined:
            return tools
        return [tool for tool in tools if tool.name not in self._quarantined]

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        name = context.message.name
        if self._block and name in self._quarantined:
            raise PolicyDenied(
                f"blocked by Bastion policy: '{name}' has changed since it was pinned. "
                "Review the change, then re-approve it with `bastion pin`."
            )
        return await call_next(context)

    def _note(self, *, name: str, message: str, blocked: bool) -> None:
        if self._writer is None:
            return
        self._writer.write(
            AuditRecord(
                tool=name,
                kind="pin",
                outcome="denied" if blocked else "error",
                error=message,
                flags=["pin:drift"],
            )
        )

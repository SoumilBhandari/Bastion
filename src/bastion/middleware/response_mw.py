"""Middleware that inspects upstream results before the agent sees them."""

from __future__ import annotations

from typing import Any

from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp.types import CallToolRequestParams

from bastion.policy import notes
from bastion.policy.injection import CAUTION
from bastion.policy.models import PolicyDenied
from bastion.policy.responses import ResponseInspector, ResponseVerdict


class ResponseGuardMiddleware(Middleware):
    """Redacts, annotates, or blocks a tool result on its way back.

    Everything the agent reads from a tool lands in the same context window as
    its instructions, so a result is not inert. Two things are worth catching
    before it gets there: credentials the agent was never meant to hold, and
    text written to steer it.

    Findings are attached to the request's audit record, so a tool that
    repeatedly returns suspicious content is visible in the log rather than
    only in the moment.
    """

    def __init__(self, inspector: ResponseInspector) -> None:
        super().__init__()
        self._inspector = inspector

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        result = await call_next(context)
        if not self._inspector.active:
            return result

        tool = context.message.name
        blocks = list(result.content or [])
        texts = [text for block in blocks if isinstance(text := getattr(block, "text", None), str)]
        structured = result.structured_content
        combined = "\n".join([*texts, self._inspector.text_of(structured)]).strip()
        if not combined:
            return result

        verdict = self._inspector.inspect(tool, combined)
        if verdict.flags:
            notes.add_flags(verdict.flags)

        if not verdict.allowed:
            raise PolicyDenied(
                f"blocked by Bastion policy: result of '{tool}' withheld — {verdict.blocked_by}"
            )
        if not (verdict.redact or verdict.caution):
            return result

        return result.model_copy(
            update={
                "content": [self._rewrite(tool, block, verdict) for block in blocks],
                "structured_content": self._inspector.apply_structured(tool, structured, verdict),
            }
        )

    def _rewrite(self, tool: str, block: Any, verdict: ResponseVerdict) -> Any:
        text = getattr(block, "text", None)
        if not isinstance(text, str):
            return block
        rewritten = self._inspector.apply(tool, text, verdict)
        if verdict.caution:
            rewritten = f"{CAUTION}\n\n{rewritten}"
        return block.model_copy(update={"text": rewritten})

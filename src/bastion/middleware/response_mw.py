"""Middleware that inspects upstream results before the agent sees them."""

from __future__ import annotations

from typing import Any

from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp.types import CallToolRequestParams, TextContent

from bastion.policy import notes
from bastion.policy.injection import CAUTION
from bastion.policy.models import PolicyDenied
from bastion.policy.responses import ResponseInspector, ResponseVerdict


def block_text(block: Any) -> str | None:
    """The text a content block carries, wherever it keeps it.

    A plain text block holds it at ``.text``, but an embedded resource — the
    ordinary way MCP servers return file contents and fetched documents — keeps
    it at ``.resource.text`` and has no ``.text`` at all. Reading only ``.text``
    meant an entire standard content type went unscanned.
    """
    text = getattr(block, "text", None)
    if isinstance(text, str):
        return text
    nested = getattr(getattr(block, "resource", None), "text", None)
    return nested if isinstance(nested, str) else None


def with_text(block: Any, replacement: str) -> Any:
    """A copy of ``block`` carrying ``replacement`` wherever its text lives."""
    if isinstance(getattr(block, "text", None), str):
        return block.model_copy(update={"text": replacement})
    resource = getattr(block, "resource", None)
    if resource is not None and isinstance(getattr(resource, "text", None), str):
        return block.model_copy(
            update={"resource": resource.model_copy(update={"text": replacement})}
        )
    return block


def caution_strings(value: Any) -> Any:
    """Prefix the caution to the top-level strings of a structured result.

    FastMCP mirrors a tool's text into ``structured_content``, and that mirror is
    what ``result.data`` returns — which many clients read in preference to the
    text blocks. Warning only the text blocks left those clients reading the
    original payload with nothing to tell them it was suspect.
    """
    if isinstance(value, str):
        return f"{CAUTION}\n\n{value}"
    if isinstance(value, dict):
        return {
            key: (f"{CAUTION}\n\n{item}" if isinstance(item, str) else item)
            for key, item in value.items()
        }
    return value


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
        structured = result.structured_content
        texts = [text for block in blocks if (text := block_text(block)) is not None]
        combined = "\n".join([*texts, self._inspector.text_of(structured)]).strip()
        if not combined:
            return result

        verdict = self._inspector.inspect(tool, combined)
        if verdict.flags:
            notes.record_flags(verdict.flags)

        if not verdict.allowed:
            raise PolicyDenied(
                f"blocked by Bastion policy: result of '{tool}' withheld — {verdict.blocked_by}"
            )
        if not (verdict.redact or verdict.caution):
            return result

        rewritten = [self._rewrite(tool, block, verdict) for block in blocks]
        if verdict.caution and not texts:
            # Nothing carried text to prefix, so the warning would be lost.
            rewritten.insert(0, TextContent(type="text", text=CAUTION))

        return result.model_copy(
            update={
                "content": rewritten,
                "structured_content": self._rewrite_structured(tool, structured, verdict),
            }
        )

    def _rewrite(self, tool: str, block: Any, verdict: ResponseVerdict) -> Any:
        text = block_text(block)
        if text is None:
            return block
        rewritten = self._inspector.apply(tool, text, verdict)
        if verdict.caution:
            rewritten = f"{CAUTION}\n\n{rewritten}"
        return with_text(block, rewritten)

    def _rewrite_structured(self, tool: str, structured: Any, verdict: ResponseVerdict) -> Any:
        rewritten = self._inspector.apply_structured(tool, structured, verdict)
        return caution_strings(rewritten) if verdict.caution else rewritten

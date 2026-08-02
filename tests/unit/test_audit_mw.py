"""Unit tests for the audit middleware."""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastmcp.tools import ToolResult
from mcp.types import TextContent

from bastion.audit import AuditWriter
from bastion.middleware.audit_mw import AuditMiddleware, _result_error


def _text(value: str) -> TextContent:
    return TextContent(type="text", text=value)


def test_successful_result_has_no_error() -> None:
    assert _result_error(ToolResult(content=[_text("fine")])) is None


def test_error_result_yields_its_message() -> None:
    result = ToolResult(content=[_text("boom: it failed")], is_error=True)
    assert _result_error(result) == "boom: it failed"


def test_error_result_joins_multiple_blocks() -> None:
    result = ToolResult(content=[_text("first"), _text("second")], is_error=True)
    assert _result_error(result) == "first\nsecond"


def test_error_result_without_text_still_reports_an_error() -> None:
    assert _result_error(ToolResult(content=[], is_error=True)) == "upstream reported an error"


def test_error_message_is_truncated() -> None:
    result = ToolResult(content=[_text("x" * 5000)], is_error=True)
    message = _result_error(result)
    assert message is not None
    assert len(message) == 2000


def test_non_tool_results_are_never_errors() -> None:
    assert _result_error(["some", "resource", "contents"]) is None
    assert _result_error(None) is None


# ------------- cancellation -------------


async def test_a_cancelled_call_is_not_recorded_as_a_success(tmp_path: Path) -> None:
    """A client disconnect cancels in-flight calls; the log must not claim they succeeded."""
    log = tmp_path / "audit.jsonl"
    middleware = AuditMiddleware(AuditWriter(log), redact_secrets=False)

    async def never_finishes(_: object) -> ToolResult:
        await asyncio.sleep(30)
        raise AssertionError("unreachable")

    context = SimpleNamespace(message=SimpleNamespace(name="payments_transfer", arguments={}))
    task = asyncio.create_task(middleware.on_call_tool(context, never_finishes))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    record = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    assert record["outcome"] == "cancelled"
    assert record["error"]

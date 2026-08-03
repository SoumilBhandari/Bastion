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


# ------------- a broken log must not break the call -------------


class _BrokenWriter:
    """A writer whose disk is full."""

    def __init__(self) -> None:
        self.attempts = 0

    def write(self, record: object) -> None:
        self.attempts += 1
        raise OSError(28, "No space left on device")


async def _call(middleware: AuditMiddleware, *, fails: bool = False) -> object:
    context = SimpleNamespace(message=SimpleNamespace(name="payments_transfer", arguments={}))

    async def call_next(_: object) -> ToolResult:
        if fails:
            raise RuntimeError("upstream said no")
        return ToolResult(content=[_text("transferred")])

    return await middleware.on_call_tool(context, call_next)


async def test_a_failed_audit_write_does_not_fail_a_completed_call() -> None:
    """The side effect already happened; telling the agent it failed invites a retry."""
    middleware = AuditMiddleware(_BrokenWriter())  # type: ignore[arg-type]

    result = await _call(middleware)

    assert result.content[0].text == "transferred"


async def test_a_failed_audit_write_does_not_mask_the_real_error() -> None:
    """The write happens in a finally; raising there would replace the real exception."""
    middleware = AuditMiddleware(_BrokenWriter())  # type: ignore[arg-type]

    with pytest.raises(RuntimeError, match="upstream said no"):
        await _call(middleware, fails=True)


async def test_a_failed_audit_write_is_reported(capsys: pytest.CaptureFixture[str]) -> None:
    """Losing records is serious; it must not be swallowed silently."""
    middleware = AuditMiddleware(_BrokenWriter())  # type: ignore[arg-type]

    await _call(middleware)

    assert "cannot write the audit log" in capsys.readouterr().err


async def test_repeated_audit_failures_are_not_reported_every_time(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A full disk fails every call; one line per call would bury the terminal."""
    middleware = AuditMiddleware(_BrokenWriter())  # type: ignore[arg-type]

    for _ in range(50):
        await _call(middleware)

    reported = capsys.readouterr().err.count("cannot write the audit log")
    assert 0 < reported < 10

"""The gateway against an HTTP upstream.

Bastion supports two upstream transports and every other end-to-end test uses
stdio, so the HTTP path — a different config branch, different connection
handling, and headers that stdio has no equivalent for — was never exercised
against a running server.
"""

import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from bastion.config.schema import BastionConfig
from bastion.gateway import build_gateway


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _await_port(port: int, *, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as probe:
            probe.settimeout(0.5)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError(f"upstream never started listening on {port}")


@pytest.fixture(scope="module")
def http_upstream() -> Iterator[str]:
    """Run the sample upstream over HTTP and yield its URL."""
    from tests.conftest import SAMPLE_UPSTREAM

    port = _free_port()
    process = subprocess.Popen(
        [sys.executable, str(SAMPLE_UPSTREAM), "http", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _await_port(port)
        yield f"http://127.0.0.1:{port}/mcp/"
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()


def _config(url: str, *, audit_path: Path | None = None, **policy: Any) -> BastionConfig:
    settings: dict[str, Any] = {"pinning": {"enabled": False}}
    settings.update(policy)
    return BastionConfig.model_validate(
        {
            "upstreams": {"remote": {"url": url}},
            "audit": (
                {"enabled": True, "path": str(audit_path)} if audit_path else {"enabled": False}
            ),
            "policy": settings,
        }
    )


async def test_tools_are_listed_from_an_http_upstream(http_upstream: str) -> None:
    async with Client(build_gateway(_config(http_upstream))) as client:
        names = {tool.name for tool in await client.list_tools()}
    assert {"echo", "add", "delete_thing"} <= names


async def test_a_call_passes_through_to_an_http_upstream(http_upstream: str) -> None:
    async with Client(build_gateway(_config(http_upstream))) as client:
        result = await client.call_tool("echo", {"text": "over http"})
    assert result.data == "over http"


async def test_policy_applies_over_http(http_upstream: str, tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    config = _config(
        http_upstream,
        audit_path=audit,
        default="allow",
        permissions=[{"tool": "delete_thing", "action": "deny"}],
    )
    async with Client(build_gateway(config)) as client:
        assert "delete_thing" not in {t.name for t in await client.list_tools()}
        with pytest.raises(ToolError, match="Bastion policy"):
            await client.call_tool("delete_thing", {"name": "x"})

    assert '"outcome": "denied"' in audit.read_text(encoding="utf-8")


async def test_response_scanning_applies_over_http(http_upstream: str) -> None:
    async with Client(build_gateway(_config(http_upstream))) as client:
        result = await client.call_tool("leak_credential", {})
    assert "***" in str(result.content)


async def test_an_unreachable_http_upstream_fails_cleanly(tmp_path: Path) -> None:
    """A dead endpoint must surface an error, not hang or leak a traceback."""
    config = _config(f"http://127.0.0.1:{_free_port()}/mcp/")
    with pytest.raises(Exception) as excinfo:
        async with Client(build_gateway(config)) as client:
            await client.call_tool("echo", {"text": "nobody home"})
    assert "Traceback" not in str(excinfo.value)

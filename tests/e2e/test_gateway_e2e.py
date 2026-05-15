"""End-to-end tests: a real MCP client through the gateway to real upstreams."""

from pathlib import Path
from typing import Any

from fastmcp import Client

from mcpwarden.config.schema import WardenConfig
from mcpwarden.gateway import build_gateway


def _config(upstreams: dict[str, dict[str, Any]]) -> WardenConfig:
    return WardenConfig.model_validate({"upstreams": upstreams})


async def test_gateway_lists_upstream_tools(sample_upstream: Path, python_exe: str) -> None:
    config = _config({"sample": {"command": python_exe, "args": [str(sample_upstream)]}})
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        names = {tool.name for tool in await client.list_tools()}
    assert {"echo", "add", "delete_thing", "write_note"} <= names


async def test_gateway_passes_through_tool_call(sample_upstream: Path, python_exe: str) -> None:
    config = _config({"sample": {"command": python_exe, "args": [str(sample_upstream)]}})
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        result = await client.call_tool("echo", {"text": "through the gateway"})
    assert result.data == "through the gateway"


async def test_gateway_passes_through_typed_result(sample_upstream: Path, python_exe: str) -> None:
    config = _config({"sample": {"command": python_exe, "args": [str(sample_upstream)]}})
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        result = await client.call_tool("add", {"a": 2, "b": 40})
    assert result.data == 42


async def test_gateway_namespaces_multiple_upstreams(
    sample_upstream: Path, python_exe: str
) -> None:
    config = _config(
        {
            "alpha": {"command": python_exe, "args": [str(sample_upstream)]},
            "beta": {"command": python_exe, "args": [str(sample_upstream)]},
        }
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        names = {tool.name for tool in await client.list_tools()}
    assert {"alpha_echo", "beta_echo"} <= names

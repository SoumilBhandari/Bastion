"""End-to-end tests: a real MCP client through the gateway to real upstreams."""

import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from bastion.config.schema import BastionConfig
from bastion.gateway import build_gateway


def _config(
    upstreams: dict[str, dict[str, Any]],
    *,
    audit_path: Path | None = None,
) -> BastionConfig:
    raw: dict[str, Any] = {"upstreams": upstreams}
    if audit_path is None:
        raw["audit"] = {"enabled": False}
    else:
        raw["audit"] = {"enabled": True, "path": str(audit_path)}
    return BastionConfig.model_validate(raw)


def _stdio(python_exe: str, sample_upstream: Path) -> dict[str, dict[str, Any]]:
    return {"sample": {"command": python_exe, "args": [str(sample_upstream)]}}


async def test_gateway_lists_upstream_tools(sample_upstream: Path, python_exe: str) -> None:
    gateway = build_gateway(_config(_stdio(python_exe, sample_upstream)))
    async with Client(gateway) as client:
        names = {tool.name for tool in await client.list_tools()}
    assert {"echo", "add", "delete_thing", "write_note"} <= names


async def test_gateway_passes_through_tool_call(sample_upstream: Path, python_exe: str) -> None:
    gateway = build_gateway(_config(_stdio(python_exe, sample_upstream)))
    async with Client(gateway) as client:
        result = await client.call_tool("echo", {"text": "through the gateway"})
    assert result.data == "through the gateway"


async def test_gateway_passes_through_typed_result(sample_upstream: Path, python_exe: str) -> None:
    gateway = build_gateway(_config(_stdio(python_exe, sample_upstream)))
    async with Client(gateway) as client:
        result = await client.call_tool("add", {"a": 2, "b": 40})
    assert result.data == 42


async def test_gateway_namespaces_multiple_upstreams(
    sample_upstream: Path, python_exe: str
) -> None:
    upstreams = {
        "alpha": {"command": python_exe, "args": [str(sample_upstream)]},
        "beta": {"command": python_exe, "args": [str(sample_upstream)]},
    }
    gateway = build_gateway(_config(upstreams))
    async with Client(gateway) as client:
        names = {tool.name for tool in await client.list_tools()}
    assert {"alpha_echo", "beta_echo"} <= names


async def test_gateway_writes_an_audit_record_per_call(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    audit_log = tmp_path / "audit.jsonl"
    gateway = build_gateway(_config(_stdio(python_exe, sample_upstream), audit_path=audit_log))
    async with Client(gateway) as client:
        await client.call_tool("echo", {"text": "hi"})
        await client.call_tool("add", {"a": 1, "b": 2})
    records = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    assert [r["tool"] for r in records] == ["echo", "add"]
    assert records[0]["arguments"] == {"text": "hi"}
    assert records[0]["outcome"] == "ok"
    assert records[0]["duration_ms"] >= 0


async def test_gateway_audit_records_a_failing_call(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    audit_log = tmp_path / "audit.jsonl"
    gateway = build_gateway(_config(_stdio(python_exe, sample_upstream), audit_path=audit_log))
    async with Client(gateway) as client:
        with pytest.raises(ToolError):
            await client.call_tool("boom", {})
    records = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 1
    assert records[0]["tool"] == "boom"
    assert records[0]["outcome"] == "error"
    assert records[0]["error"]

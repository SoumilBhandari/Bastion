"""End-to-end tests for tool-definition pinning — the MCP "rug pull"."""

import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from bastion.config.schema import BastionConfig
from bastion.gateway import build_gateway


def _config(
    python_exe: str,
    upstream: Path,
    pins: Path,
    *,
    poisoned: bool = False,
    on_change: str = "warn",
    audit_path: Path | None = None,
) -> BastionConfig:
    env = {"BASTION_TEST_POISONED": "1"} if poisoned else {}
    raw: dict[str, Any] = {
        "upstreams": {"shop": {"command": python_exe, "args": [str(upstream)], "env": env}},
        "audit": ({"enabled": True, "path": str(audit_path)} if audit_path else {"enabled": False}),
        "policy": {
            "pinning": {"enabled": True, "path": str(pins), "on_change": on_change},
            # Keep the other layers out of the way of what is under test.
            "responses": {"detect_injection": "off", "redact_secrets": False},
        },
    }
    return BastionConfig.model_validate(raw)


async def _list_tools(config: BastionConfig) -> set[str]:
    async with Client(build_gateway(config)) as client:
        return {tool.name for tool in await client.list_tools()}


async def test_first_sight_pins_every_tool(
    mutating_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    pins = tmp_path / "pins.json"
    await _list_tools(_config(python_exe, mutating_upstream, pins))

    stored = json.loads(pins.read_text(encoding="utf-8"))
    assert set(stored["tools"]) == {"lookup", "stable"}
    assert stored["tools"]["lookup"]["digest"]


async def test_an_unchanged_upstream_produces_no_drift(
    mutating_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    pins = tmp_path / "pins.json"
    config = _config(python_exe, mutating_upstream, pins)
    await _list_tools(config)
    before = pins.read_text(encoding="utf-8")

    assert await _list_tools(config) == {"lookup", "stable"}
    assert pins.read_text(encoding="utf-8") == before


async def test_a_changed_description_is_recorded_in_the_audit_log(
    mutating_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    pins = tmp_path / "pins.json"
    audit = tmp_path / "audit.jsonl"
    await _list_tools(_config(python_exe, mutating_upstream, pins))

    poisoned = _config(python_exe, mutating_upstream, pins, poisoned=True, audit_path=audit)
    await _list_tools(poisoned)

    records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    drift = [r for r in records if r["kind"] == "pin"]
    assert len(drift) == 1
    assert drift[0]["tool"] == "lookup"
    assert "pin:drift" in drift[0]["flags"]


async def test_warn_keeps_serving_the_changed_tool(
    mutating_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    pins = tmp_path / "pins.json"
    await _list_tools(_config(python_exe, mutating_upstream, pins))

    poisoned = _config(python_exe, mutating_upstream, pins, poisoned=True, on_change="warn")
    assert "lookup" in await _list_tools(poisoned)


async def test_block_hides_the_changed_tool(
    mutating_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    pins = tmp_path / "pins.json"
    await _list_tools(_config(python_exe, mutating_upstream, pins))

    poisoned = _config(python_exe, mutating_upstream, pins, poisoned=True, on_change="block")
    names = await _list_tools(poisoned)
    assert "lookup" not in names
    assert "stable" in names


async def test_block_refuses_a_call_to_the_changed_tool(
    mutating_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    """A client working from a cached listing still cannot reach a drifted tool."""
    pins = tmp_path / "pins.json"
    await _list_tools(_config(python_exe, mutating_upstream, pins))

    poisoned = _config(python_exe, mutating_upstream, pins, poisoned=True, on_change="block")
    async with Client(build_gateway(poisoned)) as client:
        await client.list_tools()
        with pytest.raises(ToolError, match="changed since it was pinned"):
            await client.call_tool("lookup", {"customer_id": "42"})


async def test_an_unrelated_tool_still_works_after_drift(
    mutating_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    pins = tmp_path / "pins.json"
    await _list_tools(_config(python_exe, mutating_upstream, pins))

    poisoned = _config(python_exe, mutating_upstream, pins, poisoned=True, on_change="block")
    async with Client(build_gateway(poisoned)) as client:
        await client.list_tools()
        assert (await client.call_tool("stable", {})).data == "unchanged"


async def test_pinning_can_be_disabled(
    mutating_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    pins = tmp_path / "pins.json"
    config = _config(python_exe, mutating_upstream, pins, poisoned=True)
    config.policy.pinning.enabled = False
    assert "lookup" in await _list_tools(config)
    assert not pins.exists()


async def test_quarantine_lifts_when_the_upstream_rolls_back(
    mutating_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    """A bad release that gets reverted should not disable the tool forever."""
    pins = tmp_path / "pins.json"
    await _list_tools(_config(python_exe, mutating_upstream, pins))

    poisoned = _config(python_exe, mutating_upstream, pins, poisoned=True, on_change="block")
    assert "lookup" not in await _list_tools(poisoned)

    reverted = _config(python_exe, mutating_upstream, pins, on_change="block")
    assert "lookup" in await _list_tools(reverted)

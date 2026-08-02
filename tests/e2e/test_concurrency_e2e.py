"""Concurrent traffic through one gateway.

Per-request state — response-guard findings, the cost charged — is carried from
the middleware that discovers it up to the middleware that writes the audit
record, on a context variable. Under asyncio each request runs in its own task
with its own copy of that context, which is what keeps one call's findings out
of another's record. These tests hold that property down, because nothing about
the code makes the mistake obvious if it regresses: flags would simply start
appearing on the wrong rows.
"""

import asyncio
import json
from pathlib import Path
from typing import Any

from fastmcp import Client

from bastion.config.schema import BastionConfig
from bastion.gateway import build_gateway


def _config(
    python_exe: str,
    upstream: Path,
    audit_path: Path,
    **policy: Any,
) -> BastionConfig:
    settings: dict[str, Any] = {"default": "allow", "pinning": {"enabled": False}}
    settings.update(policy)
    return BastionConfig.model_validate(
        {
            "upstreams": {"sample": {"command": python_exe, "args": [str(upstream)]}},
            "audit": {"enabled": True, "path": str(audit_path)},
            "policy": settings,
            **({"cost": policy.pop("cost")} if "cost" in policy else {}),
        }
    )


def _records(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


async def test_findings_do_not_leak_between_concurrent_calls(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    """A clean call running alongside a poisoned one must stay clean."""
    audit = tmp_path / "audit.jsonl"
    gateway = build_gateway(_config(python_exe, sample_upstream, audit))

    async with Client(gateway) as client:
        await asyncio.gather(
            *(
                client.call_tool("poisoned_page", {})
                if index % 3 == 0
                else client.call_tool("echo", {"text": f"clean {index}"})
                for index in range(24)
            )
        )

    records = _records(audit)
    assert len(records) == 24
    for record in records:
        flags = record.get("flags") or []
        if record["tool"] == "poisoned_page":
            assert "injection:instruction-override" in flags
        else:
            assert flags == [], f"clean call picked up {flags}"


async def test_cost_is_attributed_to_the_right_call(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    audit = tmp_path / "audit.jsonl"
    config = BastionConfig.model_validate(
        {
            "upstreams": {"sample": {"command": python_exe, "args": [str(sample_upstream)]}},
            "audit": {"enabled": True, "path": str(audit)},
            "cost": {"default_per_call": 0.001, "per_tool": {"add": 0.5}},
            "policy": {"pinning": {"enabled": False}},
        }
    )
    gateway = build_gateway(config)

    async with Client(gateway) as client:
        await asyncio.gather(
            *(
                client.call_tool("add", {"a": 1, "b": 1})
                if index % 2
                else client.call_tool("echo", {"text": "x"})
                for index in range(20)
            )
        )

    for record in _records(audit):
        assert record["cost"] == (0.5 if record["tool"] == "add" else 0.001)


async def test_the_hash_chain_survives_concurrent_writes(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    """Interleaved calls must still produce one unbroken chain."""
    from bastion.audit import verify_records

    audit = tmp_path / "audit.jsonl"
    gateway = build_gateway(_config(python_exe, sample_upstream, audit))

    async with Client(gateway) as client:
        await asyncio.gather(
            *(client.call_tool("echo", {"text": f"call {index}"}) for index in range(40))
        )

    report = verify_records(_records(audit))
    assert report.ok, report.breaks
    assert report.checked == 40


async def test_a_rate_limit_holds_under_concurrency(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    """The cap must bound what gets through, not merely what is attempted."""
    audit = tmp_path / "audit.jsonl"
    gateway = build_gateway(
        _config(
            python_exe,
            sample_upstream,
            audit,
            rate_limits=[{"name": "tight", "scope": "global", "max_per_minute": 60, "burst": 5}],
        )
    )

    async with Client(gateway) as client:
        await asyncio.gather(
            *(client.call_tool("echo", {"text": str(index)}) for index in range(30)),
            return_exceptions=True,
        )

    outcomes = [record["outcome"] for record in _records(audit)]
    # The bucket refills while the batch runs, so the exact number varies; what
    # must hold is that the cap did something and did not let everything past.
    assert outcomes.count("ok") <= 10
    assert outcomes.count("denied") >= 20


async def test_a_budget_holds_under_concurrency(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    audit = tmp_path / "audit.jsonl"
    gateway = build_gateway(
        _config(
            python_exe,
            sample_upstream,
            audit,
            budgets=[{"name": "cap", "scope": "global", "per": "hour", "max_calls": 7}],
            budget_checkpoint=str(tmp_path / "budgets.json"),
        )
    )

    async with Client(gateway) as client:
        await asyncio.gather(
            *(client.call_tool("echo", {"text": str(index)}) for index in range(25)),
            return_exceptions=True,
        )

    outcomes = [record["outcome"] for record in _records(audit)]
    assert outcomes.count("ok") == 7
    assert outcomes.count("denied") == 18

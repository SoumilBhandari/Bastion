"""Measure what Bastion costs you.

Two numbers matter. The first is how much latency the gateway adds to a tool
call, which is what an agent actually feels — measured against the same
upstream reached directly, so the upstream's own cost cancels out. The second
is how fast the policy layers are on their own, which is what determines
whether the first number can stay small as the config grows.

    python benchmarks/bench_gateway.py                  # 3 rounds x 400 calls
    python benchmarks/bench_gateway.py --rounds 5 --calls 1000
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from fastmcp import Client
from fastmcp.server import create_proxy

from bastion.audit import AuditRecord, AuditWriter
from bastion.config.schema import BastionConfig
from bastion.gateway import build_gateway
from bastion.gateway.app import build_mcp_config
from bastion.policy import PolicyEngine
from bastion.policy.injection import find_injection
from bastion.policy.secrets import redact_structure

UPSTREAM = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sample_upstream.py"

# A policy with something in every layer, so the numbers reflect real use
# rather than an empty config short-circuiting every check.
POLICY: dict[str, Any] = {
    "default": "allow",
    "permissions": [
        {"tool": "delete_*", "action": "deny"},
        {"tool": "admin_*", "action": "deny"},
        {"tool": "echo", "action": "allow"},
    ],
    "rate_limits": [
        {"name": "global", "scope": "global", "max_per_minute": 100000, "burst": 100000},
        {"name": "per-tool", "scope": "per_tool", "max_per_minute": 100000, "burst": 100000},
    ],
    "budgets": [
        {"name": "hourly", "scope": "global", "per": "hour", "max_calls": 10_000_000},
    ],
    "guards": [
        {"name": "no-etc", "arg": "$.path", "pattern": "^/etc/", "action": "block"},
        {"name": "mask", "arg": "$.token", "pattern": ".+", "action": "redact"},
    ],
}


def _config(*, audit_path: Path | None, with_policy: bool) -> BastionConfig:
    raw: dict[str, Any] = {
        "upstreams": {"sample": {"command": sys.executable, "args": [str(UPSTREAM)]}},
        "audit": ({"enabled": True, "path": str(audit_path)} if audit_path else {"enabled": False}),
        "policy": dict(POLICY) if with_policy else {},
    }
    if not with_policy:
        raw["policy"] = {"pinning": {"enabled": False}}
    else:
        raw["policy"]["pinning"] = {"enabled": False}
    return BastionConfig.model_validate(raw)


async def _time_calls(server: Any, calls: int, warmup: int = 100) -> list[float]:
    """Round-trip latencies for ``calls`` tool calls, in milliseconds."""
    samples: list[float] = []
    async with Client(server) as client:
        for _ in range(warmup):
            await client.call_tool("echo", {"text": "warmup"})
        for index in range(calls):
            started = time.perf_counter()
            await client.call_tool("echo", {"text": f"call {index}"})
            samples.append((time.perf_counter() - started) * 1000)
    return samples


def _summary(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    return {
        "mean": statistics.fmean(ordered),
        "p50": ordered[len(ordered) // 2],
        "p95": ordered[int(len(ordered) * 0.95)],
        "p99": ordered[int(len(ordered) * 0.99)],
    }


def _bench(label: str, iterations: int, operation: Callable[[int], object]) -> None:
    """Time a synchronous operation and print its per-call cost."""
    for index in range(min(iterations // 10, 1000)):
        operation(index)
    started = time.perf_counter()
    for index in range(iterations):
        operation(index)
    elapsed = time.perf_counter() - started
    per_call_us = elapsed / iterations * 1_000_000
    rate = iterations / elapsed
    print(f"  {label:<38} {per_call_us:8.2f} µs/op   {rate:>12,.0f} ops/sec")


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--calls", type=int, default=400, help="Tool calls per scenario per round.")
    parser.add_argument("--rounds", type=int, default=3, help="Interleaved measurement rounds.")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)

        print(
            f"\nEnd-to-end tool call latency "
            f"({args.rounds} rounds x {args.calls} calls, interleaved)"
        )
        print("-" * 78)

        # Build each server once, then measure them in alternating rounds. The
        # baseline drifts with whatever else the machine is doing, so measuring
        # it once up front and subtracting later produces an "overhead" that is
        # mostly noise. Interleaving makes every scenario absorb the same drift.
        servers = [
            (
                "upstream via a bare proxy",
                create_proxy(
                    build_mcp_config(_config(audit_path=None, with_policy=False)),
                    name="direct",
                ),
            ),
            (
                "through Bastion, policy only",
                build_gateway(_config(audit_path=None, with_policy=True)),
            ),
            (
                "through Bastion, policy + audit",
                build_gateway(_config(audit_path=workdir / "audit.jsonl", with_policy=True)),
            ),
        ]

        samples: dict[str, list[float]] = {label: [] for label, _ in servers}
        for _ in range(args.rounds):
            for label, server in servers:
                samples[label].extend(await _time_calls(server, args.calls))

        baseline = _summary(samples[servers[0][0]])["p50"]
        for label, _ in servers:
            result = _summary(samples[label])
            overhead = (
                f"   +{(result['p50'] - baseline) * 1000:.0f} µs" if label != servers[0][0] else ""
            )
            print(
                f"  {label:<38} {result['p50']:7.3f} ms median   "
                f"p95 {result['p95']:6.3f} ms{overhead}"
            )

        print("\nPolicy layers in isolation")
        print("-" * 78)

        engine = PolicyEngine(_config(audit_path=None, with_policy=True).policy)
        arguments = {"path": "/tmp/report.txt", "token": "abc", "body": "some content"}
        _bench("policy check (allowed)", 200_000, lambda _: engine.check("echo", arguments))
        _bench("policy check (denied)", 200_000, lambda _: engine.check("delete_x", arguments))
        _bench("guard redaction", 200_000, lambda _: engine.redact_arguments("echo", arguments))

        payload = {"cmd": ["curl", "-H", "Authorization: Bearer " + "x" * 40], "note": "hello"}
        _bench("secret redaction (arguments)", 100_000, lambda _: redact_structure(payload))

        prose = "The deployment finished successfully. " * 20
        _bench("injection scan (800 chars)", 50_000, lambda _: find_injection(prose))

        writer = AuditWriter(workdir / "bench.jsonl", max_bytes=None)
        _bench(
            "audit write (hash-chained, flushed)",
            50_000,
            lambda i: writer.write(AuditRecord(tool="echo", arguments={"i": i})),
        )
        writer.close()
        print()


if __name__ == "__main__":
    asyncio.run(main())

"""Builds the Bastion gateway — a proxy that fronts the configured upstreams.

The gateway proxies every configured upstream and runs a middleware chain: an
error boundary, optional audit logging, and policy enforcement.
"""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP
from fastmcp.server import create_proxy

from bastion.audit import AuditWriter
from bastion.config.schema import BastionConfig, Upstream
from bastion.middleware import (
    AuditMiddleware,
    ErrorBoundary,
    PinningMiddleware,
    PolicyMiddleware,
    ResponseGuardMiddleware,
    TimeoutMiddleware,
)
from bastion.policy import PolicyEngine
from bastion.policy.pinning import PinChecker, PinStore
from bastion.policy.responses import ResponseInspector

GATEWAY_NAME = "bastion"


def _upstream_to_mcp_server(upstream: Upstream) -> dict[str, Any]:
    """Translate one Bastion upstream into a FastMCP ``mcpServers`` entry."""
    entry: dict[str, Any] = {}
    if upstream.transport == "stdio":
        entry["command"] = upstream.command
        if upstream.args:
            entry["args"] = upstream.args
        if upstream.env:
            entry["env"] = upstream.env
    else:
        entry["url"] = upstream.url
        if upstream.headers:
            entry["headers"] = upstream.headers
    return entry


def build_mcp_config(config: BastionConfig) -> dict[str, Any]:
    """Assemble the FastMCP multi-server proxy config from a Bastion config."""
    return {
        "mcpServers": {
            name: _upstream_to_mcp_server(upstream) for name, upstream in config.upstreams.items()
        }
    }


def build_gateway(config: BastionConfig) -> FastMCP[Any]:
    """Build the gateway: a proxy over every configured upstream, with the
    middleware chain attached.

    The chain runs outermost-first::

        ErrorBoundary → Audit → Pinning → Policy → ResponseGuard → Timeout → upstream

    Audit sits outside Policy so denials are recorded, and Timeout sits inside
    Policy so the clock covers only the upstream call — a request that waits on
    a rate limit is not charged against its own timeout.

    With a single upstream, tools keep their original names. With several,
    FastMCP namespaces each tool by its upstream key (``<upstream>_<tool>``).
    """
    gateway = create_proxy(build_mcp_config(config), name=GATEWAY_NAME)
    gateway.add_middleware(ErrorBoundary())
    engine = PolicyEngine(config.policy, cost=config.cost)
    writer: AuditWriter | None = None
    if config.audit.enabled:
        writer = AuditWriter(
            config.audit.path,
            hash_chain=config.audit.hash_chain,
            fsync=config.audit.fsync,
            max_bytes=config.audit.max_bytes,
            keep=config.audit.keep,
        )
        gateway.add_middleware(
            AuditMiddleware(
                writer,
                log_arguments=config.audit.log_arguments,
                redact_fn=engine.redact_arguments,
                redact_secrets=config.audit.redact_secrets,
            )
        )
    pinning = config.policy.pinning
    if pinning.enabled:
        gateway.add_middleware(
            PinningMiddleware(
                PinChecker(PinStore(pinning.path)),
                block_on_change=pinning.on_change == "block",
                writer=writer,
            )
        )
    gateway.add_middleware(PolicyMiddleware(engine, hide_denied=config.policy.hide_denied))
    gateway.add_middleware(ResponseGuardMiddleware(ResponseInspector(config.policy.responses)))
    gateway.add_middleware(TimeoutMiddleware(config.timeouts))
    return gateway

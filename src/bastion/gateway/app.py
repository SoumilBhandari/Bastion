"""Builds the Bastion gateway — a proxy that fronts the configured upstreams.

The gateway proxies every configured upstream and runs a middleware chain: an
error boundary plus, when enabled, audit logging. Policy enforcement is layered
on in later milestones.
"""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP
from fastmcp.server import create_proxy

from bastion.audit import AuditWriter
from bastion.config.schema import BastionConfig, Upstream
from bastion.middleware import AuditMiddleware, ErrorBoundary

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
    error-boundary and (when enabled) audit middleware attached.

    With a single upstream, tools keep their original names. With several,
    FastMCP namespaces each tool by its upstream key (``<upstream>_<tool>``).
    """
    gateway = create_proxy(build_mcp_config(config), name=GATEWAY_NAME)
    gateway.add_middleware(ErrorBoundary())
    if config.audit.enabled:
        writer = AuditWriter(config.audit.path)
        gateway.add_middleware(AuditMiddleware(writer, log_arguments=config.audit.log_arguments))
    return gateway

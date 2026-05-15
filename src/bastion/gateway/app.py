"""Builds the Bastion gateway — a proxy that fronts the configured upstreams.

Policy enforcement and audit middleware are layered on in later milestones; at
this stage the gateway is a faithful pass-through proxy.
"""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP
from fastmcp.server import create_proxy

from bastion.config.schema import BastionConfig, Upstream

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
    """Build the gateway server that proxies every configured upstream.

    With a single upstream, tools keep their original names. With several,
    FastMCP namespaces each tool by its upstream key (``<upstream>_<tool>``).
    """
    return create_proxy(build_mcp_config(config), name=GATEWAY_NAME)

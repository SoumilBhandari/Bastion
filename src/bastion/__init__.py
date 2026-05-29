"""Bastion — a local-first control plane for your AI agent's tools.

Bastion is an MCP gateway: it sits between an AI agent and the MCP servers it
uses, enforcing budget caps, rate limits, permissions, and argument guards on
every tool call while writing a full audit log.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("bastion-mcp")
except PackageNotFoundError:  # pragma: no cover - source tree without an install
    __version__ = "0.0.0+unknown"

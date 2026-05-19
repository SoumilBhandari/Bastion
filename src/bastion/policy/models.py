"""Core policy types: the decision value and the denial exception."""

from __future__ import annotations

from dataclasses import dataclass

from fastmcp.exceptions import ToolError


@dataclass(frozen=True)
class PolicyDecision:
    """The outcome of evaluating policy for a single tool call."""

    allowed: bool
    reason: str


class PolicyDenied(ToolError):
    """Raised when a tool call is blocked by policy.

    Subclasses ``ToolError`` so the denial surfaces cleanly to the calling
    agent and passes through the gateway's error boundary unchanged.
    """

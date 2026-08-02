"""Core policy types: the decision value and the denial exception."""

from __future__ import annotations

from dataclasses import dataclass

from fastmcp.exceptions import ToolError


@dataclass(frozen=True)
class PolicyDecision:
    """The outcome of evaluating policy for a single tool call."""

    allowed: bool
    reason: str


@dataclass(frozen=True)
class ExplanationStep:
    """One policy layer's verdict on a call, with the reasoning behind it."""

    layer: str
    allowed: bool
    detail: str
    skipped: bool = False


@dataclass(frozen=True)
class Explanation:
    """Every layer's verdict on one call — the answer to "why was this denied?".

    Unlike a :class:`PolicyDecision`, which stops at the first denial, this
    keeps going, so a call blocked by several layers at once shows all of them
    rather than only the first.
    """

    tool: str
    steps: list[ExplanationStep]
    cost: float

    @property
    def allowed(self) -> bool:
        return all(step.allowed for step in self.steps)

    @property
    def blockers(self) -> list[ExplanationStep]:
        return [step for step in self.steps if not step.allowed]


class PolicyDenied(ToolError):
    """Raised when a tool call is blocked by policy.

    Subclasses ``ToolError`` so the denial surfaces cleanly to the calling
    agent and passes through the gateway's error boundary unchanged.
    """

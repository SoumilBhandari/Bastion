"""The policy engine — evaluates policy for each tool call."""

from __future__ import annotations

from bastion.config.schema import PolicyConfig
from bastion.policy.models import PolicyDecision
from bastion.policy.permissions import PermissionChecker


class PolicyEngine:
    """Evaluates policy for every tool call that reaches the gateway.

    At this milestone the engine runs permission checks only; rate limits,
    budgets, and argument guards are layered in by later milestones.
    """

    def __init__(self, policy: PolicyConfig) -> None:
        self._permissions = PermissionChecker(policy.permissions, policy.default)

    def check(self, tool: str) -> PolicyDecision:
        """Decide whether the given tool call is allowed."""
        return self._permissions.check(tool)

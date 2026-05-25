"""The policy engine — evaluates policy for each tool call."""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any

from bastion.config.schema import CostConfig, PolicyConfig
from bastion.policy.budget import BudgetTracker, CostModel, DateTimeFn, utc_now
from bastion.policy.guards import GuardEngine
from bastion.policy.models import PolicyDecision
from bastion.policy.permissions import PermissionChecker
from bastion.policy.ratelimit import Clock, RateLimiter


class PolicyEngine:
    """Evaluates policy for every tool call that reaches the gateway.

    The engine runs in two phases:

    * :meth:`check` is a read-only "peek" — runs permissions, argument
      guards, the rate-limit peek, and the budget peek in that order.
      It does not consume rate-limit tokens or increment budget counters.
    * :meth:`reserve` is called after a successful check and atomically
      consumes one token from each rate-limit rule and increments each
      applicable budget counter.

    :meth:`redact_arguments` returns a copy of the call's arguments with
    every ``action='redact'`` guard applied; the audit middleware uses this
    to keep secrets out of the audit log.

    Splitting peek from reserve lets the middleware decide before any state
    mutation and keeps the hot path correct under single-threaded asyncio
    (peek + reserve can run between awaits without interleaving).
    """

    def __init__(
        self,
        policy: PolicyConfig,
        *,
        cost: CostConfig | None = None,
        clock: Clock = time.monotonic,
        now: DateTimeFn = utc_now,
    ) -> None:
        self._permissions = PermissionChecker(policy.permissions, policy.default)
        self._rate_limiter = RateLimiter(policy.rate_limits, clock=clock)
        self._cost_model = CostModel(cost or CostConfig())
        checkpoint = policy.budget_checkpoint if policy.budgets else None
        self._budgets = BudgetTracker(policy.budgets, now=now, checkpoint_path=checkpoint)
        self._guards = GuardEngine(policy.guards)

    def check(
        self,
        tool: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> PolicyDecision:
        """Peek: decide whether the given tool call is allowed.

        Permission rules are evaluated first; on a permission denial the
        guard, rate-limit, and budget checks are skipped (denied calls do
        not consume tokens or count against budgets). When ``arguments`` is
        ``None`` the argument-guard check is skipped.
        """
        permission = self._permissions.check(tool)
        if not permission.allowed:
            return permission
        if arguments is not None:
            ok, reason = self._guards.check_blocking(tool, arguments)
            if not ok:
                return PolicyDecision(allowed=False, reason=reason or "blocked by guard")
        ok, reason = self._rate_limiter.peek(tool)
        if not ok:
            return PolicyDecision(allowed=False, reason=reason or "rate-limited")
        cost = self._cost_model.cost_for(tool)
        ok, reason = self._budgets.peek(tool, cost)
        if not ok:
            return PolicyDecision(allowed=False, reason=reason or "over budget")
        return permission

    def reserve(self, tool: str) -> None:
        """Consume rate-limit tokens and increment budget counters.

        Call after :meth:`check` returned an allowed decision.
        """
        self._rate_limiter.reserve(tool)
        cost = self._cost_model.cost_for(tool)
        self._budgets.reserve(tool, cost)

    def redact_arguments(self, tool: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        """Apply every ``action='redact'`` guard and return a redacted copy."""
        return self._guards.redact(tool, arguments)

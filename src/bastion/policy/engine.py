"""The policy engine — evaluates policy for each tool call."""

from __future__ import annotations

import time

from bastion.config.schema import PolicyConfig
from bastion.policy.models import PolicyDecision
from bastion.policy.permissions import PermissionChecker
from bastion.policy.ratelimit import Clock, RateLimiter


class PolicyEngine:
    """Evaluates policy for every tool call that reaches the gateway.

    The engine runs in two phases:

    * :meth:`check` is a read-only "peek" — runs permissions, then a
      rate-limit peek. It does not consume rate-limit tokens.
    * :meth:`reserve` is called after a successful check and atomically
      consumes one token from each rate-limit rule.

    Splitting peek from reserve lets the middleware decide before any state
    mutation and keeps the hot path correct under single-threaded asyncio
    (peek + reserve can run between awaits without interleaving).
    """

    def __init__(self, policy: PolicyConfig, *, clock: Clock = time.monotonic) -> None:
        self._permissions = PermissionChecker(policy.permissions, policy.default)
        self._rate_limiter = RateLimiter(policy.rate_limits, clock=clock)

    def check(self, tool: str) -> PolicyDecision:
        """Peek: decide whether the given tool call is allowed.

        Permission rules are evaluated first; on a permission denial the
        rate-limit check is skipped (denied calls do not consume tokens).
        """
        permission = self._permissions.check(tool)
        if not permission.allowed:
            return permission
        ok, reason = self._rate_limiter.peek(tool)
        if not ok:
            return PolicyDecision(allowed=False, reason=reason or "rate-limited")
        return permission

    def reserve(self, tool: str) -> None:
        """Consume one token from each rate-limit rule.

        Call after :meth:`check` returned an allowed decision.
        """
        self._rate_limiter.reserve(tool)

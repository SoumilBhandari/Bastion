"""Token-bucket rate limiting primitives."""

from __future__ import annotations

import time
from collections.abc import Callable

from bastion.config.schema import RateLimitRule

Clock = Callable[[], float]


class TokenBucket:
    """A token bucket that refills at a fixed rate up to a capacity.

    The bucket is refilled lazily on each :meth:`peek` or :meth:`consume` using
    a monotonic clock; ``capacity`` is the burst size and ``refill_per_second``
    sets the long-term throughput.
    """

    def __init__(
        self,
        capacity: float,
        refill_per_second: float,
        *,
        clock: Clock = time.monotonic,
    ) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if refill_per_second <= 0:
            raise ValueError("refill_per_second must be positive")
        self._capacity = float(capacity)
        self._refill_rate = float(refill_per_second)
        self._tokens = float(capacity)
        self._clock = clock
        self._last_refill = clock()

    @property
    def tokens(self) -> float:
        """Current token count, refilled lazily. Primarily for inspection."""
        self._refill()
        return self._tokens

    def _refill(self) -> None:
        now = self._clock()
        elapsed = now - self._last_refill
        if elapsed > 0:
            self._tokens = min(self._capacity, self._tokens + elapsed * self._refill_rate)
            self._last_refill = now

    def peek(self) -> bool:
        """Whether at least one token is available right now."""
        self._refill()
        return self._tokens >= 1.0

    def consume(self) -> bool:
        """Consume one token if available. Returns ``True`` on success."""
        self._refill()
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


class RateLimiter:
    """Evaluates a list of rate-limit rules against tool calls.

    Each rule maintains its own token bucket(s). ``scope`` decides granularity:
    ``global`` shares one bucket across every call; ``per_tool`` keeps one
    bucket per distinct tool name.

    Use :meth:`peek` to test whether a call is allowed (no consumption), and
    :meth:`reserve` to consume one token from every rule's matching bucket.
    """

    def __init__(self, rules: list[RateLimitRule], *, clock: Clock = time.monotonic) -> None:
        self._rules = list(rules)
        self._clock = clock
        self._buckets: dict[tuple[int, str], TokenBucket] = {}

    @staticmethod
    def _key(rule: RateLimitRule, tool: str) -> str:
        return tool if rule.scope == "per_tool" else ""

    def _bucket(self, rule_index: int, rule: RateLimitRule, tool: str) -> TokenBucket:
        key = (rule_index, self._key(rule, tool))
        bucket = self._buckets.get(key)
        if bucket is None:
            burst = float(rule.burst if rule.burst is not None else rule.max_per_minute)
            refill_per_second = rule.max_per_minute / 60.0
            bucket = TokenBucket(burst, refill_per_second, clock=self._clock)
            self._buckets[key] = bucket
        return bucket

    def peek(self, tool: str) -> tuple[bool, str | None]:
        """Check whether every rule allows this call.

        Returns ``(True, None)`` if every rule has a token; otherwise
        ``(False, reason)`` naming the first rule that blocked it.
        """
        for index, rule in enumerate(self._rules):
            bucket = self._bucket(index, rule, tool)
            if not bucket.peek():
                return False, f"rate-limited by rule '{rule.name}'"
        return True, None

    def reserve(self, tool: str) -> None:
        """Consume one token from every rule's matching bucket.

        Call this only after :meth:`peek` returned ``(True, None)``. Under
        single-threaded asyncio (between two awaits) the peek and reserve are
        effectively atomic.
        """
        for index, rule in enumerate(self._rules):
            self._bucket(index, rule, tool).consume()

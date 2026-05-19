"""Unit tests for token-bucket rate limiting."""

from __future__ import annotations

import pytest

from bastion.config.schema import RateLimitRule
from bastion.policy.ratelimit import RateLimiter, TokenBucket


class FakeClock:
    """A controllable monotonic clock for deterministic time-based tests."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# ------------- TokenBucket -------------


def test_bucket_starts_full_at_capacity() -> None:
    bucket = TokenBucket(capacity=5, refill_per_second=1, clock=FakeClock())
    assert bucket.tokens == 5.0


def test_consume_succeeds_until_empty() -> None:
    bucket = TokenBucket(capacity=3, refill_per_second=1, clock=FakeClock())
    assert bucket.consume()
    assert bucket.consume()
    assert bucket.consume()
    assert not bucket.consume()


def test_peek_does_not_consume() -> None:
    bucket = TokenBucket(capacity=2, refill_per_second=1, clock=FakeClock())
    assert bucket.peek()
    assert bucket.peek()
    assert bucket.tokens == 2.0


def test_refill_with_elapsed_time() -> None:
    clock = FakeClock()
    bucket = TokenBucket(capacity=10, refill_per_second=2, clock=clock)
    for _ in range(10):
        assert bucket.consume()
    assert not bucket.consume()
    clock.advance(3)
    assert bucket.tokens == 6.0


def test_refill_is_capped_at_capacity() -> None:
    clock = FakeClock()
    bucket = TokenBucket(capacity=5, refill_per_second=10, clock=clock)
    bucket.consume()
    clock.advance(60)
    assert bucket.tokens == 5.0


def test_rejects_invalid_parameters() -> None:
    with pytest.raises(ValueError):
        TokenBucket(capacity=0, refill_per_second=1)
    with pytest.raises(ValueError):
        TokenBucket(capacity=1, refill_per_second=0)


# ------------- RateLimiter -------------


def test_empty_rules_always_allows() -> None:
    limiter = RateLimiter([])
    ok, reason = limiter.peek("any_tool")
    assert ok
    assert reason is None


def test_global_rule_shares_bucket_across_tools() -> None:
    rule = RateLimitRule(name="global-cap", scope="global", max_per_minute=60, burst=2)
    limiter = RateLimiter([rule], clock=FakeClock())
    assert limiter.peek("tool_a")[0]
    limiter.reserve("tool_a")
    assert limiter.peek("tool_b")[0]
    limiter.reserve("tool_b")
    ok, reason = limiter.peek("tool_c")
    assert not ok
    assert reason is not None and "global-cap" in reason


def test_per_tool_scope_keeps_separate_buckets() -> None:
    rule = RateLimitRule(name="per-tool", scope="per_tool", max_per_minute=60, burst=1)
    limiter = RateLimiter([rule], clock=FakeClock())
    limiter.reserve("tool_a")
    assert not limiter.peek("tool_a")[0]
    assert limiter.peek("tool_b")[0]


def test_peek_does_not_consume_tokens() -> None:
    rule = RateLimitRule(name="cap", scope="global", max_per_minute=60, burst=1)
    limiter = RateLimiter([rule], clock=FakeClock())
    for _ in range(5):
        assert limiter.peek("tool")[0]
    limiter.reserve("tool")
    assert not limiter.peek("tool")[0]


def test_multiple_rules_must_all_allow() -> None:
    burst = RateLimitRule(name="burst", scope="global", max_per_minute=120, burst=2)
    sustained = RateLimitRule(name="sustained", scope="global", max_per_minute=60, burst=10)
    limiter = RateLimiter([burst, sustained], clock=FakeClock())
    assert limiter.peek("tool")[0]
    limiter.reserve("tool")
    limiter.reserve("tool")
    ok, reason = limiter.peek("tool")
    assert not ok
    assert reason is not None and "burst" in reason


def test_default_burst_falls_back_to_max_per_minute() -> None:
    rule = RateLimitRule(name="no-burst", scope="global", max_per_minute=5)
    limiter = RateLimiter([rule], clock=FakeClock())
    for _ in range(5):
        assert limiter.peek("tool")[0]
        limiter.reserve("tool")
    assert not limiter.peek("tool")[0]


def test_tokens_refill_over_time() -> None:
    clock = FakeClock()
    rule = RateLimitRule(name="cap", scope="global", max_per_minute=60, burst=1)
    limiter = RateLimiter([rule], clock=clock)
    limiter.reserve("tool")
    assert not limiter.peek("tool")[0]
    clock.advance(2)
    assert limiter.peek("tool")[0]

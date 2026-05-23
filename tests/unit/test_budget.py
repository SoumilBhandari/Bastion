"""Unit tests for budget tracking."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from bastion.config.schema import CostConfig
from bastion.policy.budget import BudgetCounter, CostModel


class FakeUTC:
    """Controllable UTC-datetime function for budget-window tests."""

    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += timedelta(**kwargs)


def _at(year: int, month: int, day: int, hour: int = 0, minute: int = 0) -> datetime:
    return datetime(year, month, day, hour, minute, tzinfo=UTC)


def test_cost_falls_back_to_default() -> None:
    model = CostModel(CostConfig(default_per_call=0.01))
    assert model.cost_for("anything") == 0.01


def test_cost_uses_per_tool_override() -> None:
    model = CostModel(CostConfig(default_per_call=0.01, per_tool={"search_web": 0.10}))
    assert model.cost_for("search_web") == 0.10
    assert model.cost_for("echo") == 0.01


def test_cost_is_zero_when_unset() -> None:
    model = CostModel(CostConfig())
    assert model.cost_for("anything") == 0.0


# ------------- BudgetCounter -------------


def test_budget_counter_starts_at_zero() -> None:
    counter = BudgetCounter("day", max_calls=10, now=FakeUTC(_at(2026, 5, 19)))
    assert counter.calls == 0
    assert counter.cost == 0.0


def test_budget_counter_requires_at_least_one_cap() -> None:
    with pytest.raises(ValueError):
        BudgetCounter("day", now=FakeUTC(_at(2026, 5, 19)))


def test_budget_counter_peek_allows_under_call_cap() -> None:
    counter = BudgetCounter("day", max_calls=2, now=FakeUTC(_at(2026, 5, 19)))
    assert counter.peek(0.0)
    counter.reserve(0.0)
    assert counter.peek(0.0)
    counter.reserve(0.0)
    assert not counter.peek(0.0)


def test_budget_counter_blocks_when_cost_would_exceed() -> None:
    counter = BudgetCounter("day", max_cost=1.0, now=FakeUTC(_at(2026, 5, 19)))
    assert counter.peek(0.5)
    counter.reserve(0.5)
    assert counter.peek(0.5)  # 0.5 + 0.5 == 1.0, still fits
    counter.reserve(0.5)
    assert not counter.peek(0.01)  # would push over


def test_budget_counter_both_caps_apply() -> None:
    counter = BudgetCounter(
        "day", max_calls=10, max_cost=1.0, now=FakeUTC(_at(2026, 5, 19))
    )
    counter.reserve(0.6)
    assert not counter.peek(0.5)  # cost would exceed
    assert counter.peek(0.4)  # cost is fine


def test_budget_counter_rolls_at_day_boundary() -> None:
    clock = FakeUTC(_at(2026, 5, 19, 23, 59))
    counter = BudgetCounter("day", max_calls=1, now=clock)
    counter.reserve(0.0)
    assert not counter.peek(0.0)
    clock.advance(minutes=2)
    assert counter.peek(0.0)
    assert counter.calls == 0


def test_budget_counter_rolls_at_hour_boundary() -> None:
    clock = FakeUTC(_at(2026, 5, 19, 14, 59))
    counter = BudgetCounter("hour", max_calls=1, now=clock)
    counter.reserve(0.0)
    assert not counter.peek(0.0)
    clock.advance(minutes=2)
    assert counter.peek(0.0)


def test_budget_counter_rolls_at_minute_boundary() -> None:
    clock = FakeUTC(_at(2026, 5, 19, 14, 30))
    counter = BudgetCounter("minute", max_calls=1, now=clock)
    counter.reserve(0.0)
    assert not counter.peek(0.0)
    clock.advance(seconds=61)
    assert counter.peek(0.0)

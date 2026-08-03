"""Unit tests for budget tracking."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

import pytest

from bastion.config.schema import BudgetRule, CostConfig
from bastion.policy.budget import BudgetCounter, BudgetTracker, CostModel


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
    counter = BudgetCounter("day", max_calls=10, max_cost=1.0, now=FakeUTC(_at(2026, 5, 19)))
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


# ------------- BudgetTracker -------------


def _rule(
    name: str,
    *,
    scope: Literal["global", "per_tool"] = "global",
    per: Literal["minute", "hour", "day"] = "day",
    max_calls: int | None = None,
    max_cost: float | None = None,
) -> BudgetRule:
    return BudgetRule(
        name=name,
        scope=scope,
        per=per,
        max_calls=max_calls,
        max_cost=max_cost,
    )


def test_tracker_empty_rules_always_allows() -> None:
    tracker = BudgetTracker([], now=FakeUTC(_at(2026, 5, 19)))
    ok, reason = tracker.peek("anything", 1.0)
    assert ok
    assert reason is None


def test_tracker_global_rule_shares_counter_across_tools() -> None:
    rules = [_rule("daily-cap", max_calls=2)]
    tracker = BudgetTracker(rules, now=FakeUTC(_at(2026, 5, 19)))
    tracker.reserve("a", 0.0)
    tracker.reserve("b", 0.0)
    ok, reason = tracker.peek("c", 0.0)
    assert not ok
    assert reason is not None and "daily-cap" in reason


def test_tracker_per_tool_rule_isolates_counters() -> None:
    rules = [_rule("per-tool-cap", scope="per_tool", max_calls=1)]
    tracker = BudgetTracker(rules, now=FakeUTC(_at(2026, 5, 19)))
    tracker.reserve("a", 0.0)
    ok_a, _ = tracker.peek("a", 0.0)
    ok_b, _ = tracker.peek("b", 0.0)
    assert not ok_a
    assert ok_b


def test_tracker_multiple_rules_must_all_allow() -> None:
    rules = [
        _rule("cost-cap", max_cost=1.0),
        _rule("call-cap", max_calls=10),
    ]
    tracker = BudgetTracker(rules, now=FakeUTC(_at(2026, 5, 19)))
    tracker.reserve("t", 0.9)
    ok, reason = tracker.peek("t", 0.2)
    assert not ok
    assert reason is not None and "cost-cap" in reason


def test_tracker_peek_does_not_consume() -> None:
    rules = [_rule("cap", max_calls=1)]
    tracker = BudgetTracker(rules, now=FakeUTC(_at(2026, 5, 19)))
    for _ in range(5):
        assert tracker.peek("t", 0.0)[0]
    tracker.reserve("t", 0.0)
    assert not tracker.peek("t", 0.0)[0]


# ------------- checkpoint persistence -------------


def test_counter_state_round_trips() -> None:
    clock = FakeUTC(_at(2026, 5, 19))
    counter = BudgetCounter("day", max_calls=10, max_cost=5.0, now=clock)
    counter.reserve(1.0)
    counter.reserve(2.0)
    state = counter.state()

    restored = BudgetCounter("day", max_calls=10, max_cost=5.0, now=clock)
    restored.restore(state)
    assert restored.calls == 2
    assert restored.cost == 3.0


def test_tracker_persists_state_to_disk(tmp_path: Path) -> None:
    path = tmp_path / "budget.json"
    rules = [_rule("cap", max_calls=10)]
    tracker = BudgetTracker(rules, now=FakeUTC(_at(2026, 5, 19)), checkpoint_path=path)
    tracker.reserve("t", 0.0)
    tracker.reserve("t", 0.0)
    assert path.exists()


def test_tracker_restores_state_on_restart(tmp_path: Path) -> None:
    path = tmp_path / "budget.json"
    rules = [_rule("cap", max_calls=2)]
    clock = FakeUTC(_at(2026, 5, 19))

    tracker1 = BudgetTracker(rules, now=clock, checkpoint_path=path)
    tracker1.reserve("t", 0.0)
    tracker1.reserve("t", 0.0)
    assert not tracker1.peek("t", 0.0)[0]

    # "Restart" — fresh tracker loads state from disk
    tracker2 = BudgetTracker(rules, now=clock, checkpoint_path=path)
    assert not tracker2.peek("t", 0.0)[0]


def test_tracker_handles_missing_checkpoint(tmp_path: Path) -> None:
    path = tmp_path / "nonexistent.json"
    rules = [_rule("cap", max_calls=2)]
    tracker = BudgetTracker(rules, now=FakeUTC(_at(2026, 5, 19)), checkpoint_path=path)
    assert tracker.peek("t", 0.0)[0]


def test_tracker_window_rolls_after_restart(tmp_path: Path) -> None:
    path = tmp_path / "budget.json"
    rules = [_rule("cap", max_calls=1)]

    clock1 = FakeUTC(_at(2026, 5, 19))
    tracker1 = BudgetTracker(rules, now=clock1, checkpoint_path=path)
    tracker1.reserve("t", 0.0)
    assert not tracker1.peek("t", 0.0)[0]

    # Restart on the next day -> window rolls, counters reset
    clock2 = FakeUTC(_at(2026, 5, 20))
    tracker2 = BudgetTracker(rules, now=clock2, checkpoint_path=path)
    assert tracker2.peek("t", 0.0)[0]


def test_tracker_tolerates_corrupt_checkpoint(tmp_path: Path) -> None:
    path = tmp_path / "budget.json"
    path.write_text("this is not json{{{", encoding="utf-8")
    tracker = BudgetTracker(
        [_rule("cap", max_calls=2)], now=FakeUTC(_at(2026, 5, 19)), checkpoint_path=path
    )
    assert tracker.peek("t", 0.0)[0]  # started fresh rather than crashing


def test_tracker_skips_malformed_checkpoint_entries(tmp_path: Path) -> None:
    path = tmp_path / "budget.json"
    path.write_text(
        '{"nocolon": {"window": "x", "calls": 1, "cost": 0.0}, '
        '"9:": {"window": "x", "calls": 1, "cost": 0.0}, '
        '"0:": {"calls": "oops"}}',
        encoding="utf-8",
    )
    tracker = BudgetTracker(
        [_rule("cap", max_calls=2)], now=FakeUTC(_at(2026, 5, 19)), checkpoint_path=path
    )
    assert tracker.peek("t", 0.0)[0]  # every entry skipped; counter is fresh


def test_tracker_loads_valid_entry_alongside_garbage(tmp_path: Path) -> None:
    path = tmp_path / "budget.json"
    path.write_text(
        '{"0:": {"window": "2026-05-19", "calls": 2, "cost": 0.0}, "garbage": 5}',
        encoding="utf-8",
    )
    tracker = BudgetTracker(
        [_rule("cap", max_calls=2)], now=FakeUTC(_at(2026, 5, 19)), checkpoint_path=path
    )
    # rule 0 restored at its cap of 2 calls -> the next call is over budget
    assert not tracker.peek("t", 0.0)[0]


def test_tracker_ignores_stale_rule_entries(tmp_path: Path) -> None:
    path = tmp_path / "budget.json"
    # First run with two rules
    rules_v1 = [_rule("a", max_calls=10), _rule("b", max_calls=10)]
    clock = FakeUTC(_at(2026, 5, 19))
    tracker1 = BudgetTracker(rules_v1, now=clock, checkpoint_path=path)
    tracker1.reserve("t", 0.0)

    # Second run with only one rule — the stale "1:..." entry is dropped
    rules_v2 = [_rule("a", max_calls=10)]
    tracker2 = BudgetTracker(rules_v2, now=clock, checkpoint_path=path)
    # Loaded counter for rule 0 is still there
    ok, _ = tracker2.peek("t", 0.0)
    assert ok


# ------------- a checkpoint that says something impossible -------------


def test_a_negative_call_count_in_a_checkpoint_is_clamped(tmp_path: Path) -> None:
    """A negative counter would hand back budget that had already been spent."""
    checkpoint = tmp_path / "budgets.json"
    checkpoint.write_text(
        json.dumps({"0:": {"window": "2026-08-03", "calls": -999, "cost": 0.0}}),
        encoding="utf-8",
    )
    rules = [BudgetRule(name="cap", scope="global", per="day", max_calls=2)]
    tracker = BudgetTracker(
        rules, now=lambda: datetime(2026, 8, 3, tzinfo=UTC), checkpoint_path=checkpoint
    )

    for _ in range(2):
        assert tracker.peek("x", 0.0)[0]
        tracker.reserve("x", 0.0)
    assert not tracker.peek("x", 0.0)[0]


def test_a_negative_cost_in_a_checkpoint_is_clamped(tmp_path: Path) -> None:
    checkpoint = tmp_path / "budgets.json"
    checkpoint.write_text(
        json.dumps({"0:": {"window": "2026-08-03", "calls": 0, "cost": -1000.0}}),
        encoding="utf-8",
    )
    rules = [BudgetRule(name="spend", scope="global", per="day", max_cost=1.0)]
    tracker = BudgetTracker(
        rules, now=lambda: datetime(2026, 8, 3, tzinfo=UTC), checkpoint_path=checkpoint
    )

    tracker.reserve("x", 1.0)
    assert not tracker.peek("x", 0.01)[0]

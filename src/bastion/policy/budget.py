"""Budget tracking — counts and costs over fixed time windows."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from bastion.config.schema import BudgetRule, CostConfig

Period = Literal["minute", "hour", "day"]
DateTimeFn = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)


def _window_key(now: datetime, period: Period) -> str:
    """Sortable key for the fixed window that ``now`` falls into."""
    if period == "minute":
        return now.strftime("%Y-%m-%dT%H:%M")
    if period == "hour":
        return now.strftime("%Y-%m-%dT%H")
    return now.strftime("%Y-%m-%d")


class CostModel:
    """Resolves the cost of a tool call from a :class:`CostConfig`.

    Tools listed in ``per_tool`` use their configured cost; everything else
    falls back to ``default_per_call``.
    """

    def __init__(self, config: CostConfig) -> None:
        self._default = config.default_per_call
        self._per_tool = dict(config.per_tool)

    def cost_for(self, tool: str) -> float:
        return self._per_tool.get(tool, self._default)


class BudgetCounter:
    """Tracks one budget rule's counters within its current fixed window.

    When the wall clock crosses the window boundary (UTC), the counters reset
    to zero on the next access. The constructor accepts an injected
    ``now`` for deterministic testing.
    """

    def __init__(
        self,
        period: Period,
        *,
        max_calls: int | None = None,
        max_cost: float | None = None,
        now: DateTimeFn = utc_now,
    ) -> None:
        if max_calls is None and max_cost is None:
            raise ValueError("at least one of max_calls or max_cost must be set")
        self._period = period
        self._max_calls = max_calls
        self._max_cost = max_cost
        self._now = now
        self._window: str = _window_key(now(), period)
        self._calls = 0
        self._cost = 0.0

    def _maybe_roll(self) -> None:
        current = _window_key(self._now(), self._period)
        if current != self._window:
            self._window = current
            self._calls = 0
            self._cost = 0.0

    @property
    def calls(self) -> int:
        self._maybe_roll()
        return self._calls

    @property
    def cost(self) -> float:
        self._maybe_roll()
        return self._cost

    def peek(self, cost: float) -> bool:
        """Whether one more call costing ``cost`` would still fit in the window."""
        self._maybe_roll()
        over_calls = self._max_calls is not None and self._calls + 1 > self._max_calls
        over_cost = self._max_cost is not None and self._cost + cost > self._max_cost
        return not (over_calls or over_cost)

    def reserve(self, cost: float) -> None:
        """Record one call of ``cost`` against this rule's window."""
        self._maybe_roll()
        self._calls += 1
        self._cost += cost

    def state(self) -> dict[str, Any]:
        """Export the counter's current state for checkpointing."""
        self._maybe_roll()
        return {"window": self._window, "calls": self._calls, "cost": self._cost}

    def restore(self, state: dict[str, Any]) -> None:
        """Replace the counter's state with a previously exported snapshot.

        The next access (peek/reserve) will roll the window forward if the
        snapshot is from an earlier window, resetting the counters.
        """
        self._window = str(state["window"])
        self._calls = int(state["calls"])
        self._cost = float(state["cost"])


class BudgetTracker:
    """Coordinates a list of budget rules against tool calls.

    Each rule gets its own :class:`BudgetCounter`(s); ``scope`` decides
    granularity: ``global`` shares one counter, ``per_tool`` keeps a
    separate counter per distinct tool name.

    Use :meth:`peek` to test whether a call is allowed (no mutation), and
    :meth:`reserve` to record the call against every rule.
    """

    def __init__(
        self,
        rules: list[BudgetRule],
        *,
        now: DateTimeFn = utc_now,
        checkpoint_path: Path | None = None,
    ) -> None:
        self._rules = list(rules)
        self._now = now
        self._counters: dict[tuple[int, str], BudgetCounter] = {}
        self._checkpoint_path = checkpoint_path
        self._load()

    @staticmethod
    def _scope_key(rule: BudgetRule, tool: str) -> str:
        return tool if rule.scope == "per_tool" else ""

    def _counter(self, rule_index: int, rule: BudgetRule, tool: str) -> BudgetCounter:
        key = (rule_index, self._scope_key(rule, tool))
        counter = self._counters.get(key)
        if counter is None:
            counter = BudgetCounter(
                rule.per,
                max_calls=rule.max_calls,
                max_cost=rule.max_cost,
                now=self._now,
            )
            self._counters[key] = counter
        return counter

    def peek(self, tool: str, cost: float) -> tuple[bool, str | None]:
        """Check whether every applicable budget rule allows this call."""
        for index, rule in enumerate(self._rules):
            counter = self._counter(index, rule, tool)
            if not counter.peek(cost):
                return False, f"over budget '{rule.name}'"
        return True, None

    def reserve(self, tool: str, cost: float) -> None:
        """Record one call of ``cost`` against every applicable budget rule."""
        for index, rule in enumerate(self._rules):
            self._counter(index, rule, tool).reserve(cost)
        self._save()

    def _load(self) -> None:
        if self._checkpoint_path is None or not self._checkpoint_path.exists():
            return
        try:
            raw = json.loads(self._checkpoint_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return  # unreadable or corrupt checkpoint — start fresh rather than crash
        if not isinstance(raw, dict):
            return
        for key_str, state in raw.items():
            try:
                rule_idx_str, scope_key = str(key_str).split(":", 1)
                rule_idx = int(rule_idx_str)
            except ValueError:
                continue  # malformed key — skip this entry
            if rule_idx >= len(self._rules) or not isinstance(state, dict):
                continue  # stale rule index, or non-object entry
            rule = self._rules[rule_idx]
            counter = BudgetCounter(
                rule.per,
                max_calls=rule.max_calls,
                max_cost=rule.max_cost,
                now=self._now,
            )
            try:
                counter.restore(state)
            except (KeyError, TypeError, ValueError):
                continue  # malformed entry — skip rather than crash
            self._counters[(rule_idx, scope_key)] = counter

    def _save(self) -> None:
        if self._checkpoint_path is None:
            return
        state = {
            f"{rule_idx}:{scope_key}": counter.state()
            for (rule_idx, scope_key), counter in self._counters.items()
        }
        tmp = self._checkpoint_path.with_suffix(self._checkpoint_path.suffix + ".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        tmp.replace(self._checkpoint_path)

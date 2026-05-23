"""Budget tracking — counts and costs over fixed time windows."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal

from bastion.config.schema import CostConfig

Period = Literal["minute", "hour", "day"]
DateTimeFn = Callable[[], datetime]


def _utc_now() -> datetime:
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
        now: DateTimeFn = _utc_now,
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
        if self._max_calls is not None and self._calls + 1 > self._max_calls:
            return False
        if self._max_cost is not None and self._cost + cost > self._max_cost:
            return False
        return True

    def reserve(self, cost: float) -> None:
        """Record one call of ``cost`` against this rule's window."""
        self._maybe_roll()
        self._calls += 1
        self._cost += cost

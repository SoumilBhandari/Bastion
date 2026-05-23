"""Unit tests for the policy engine — permission rules and decisions."""

from datetime import UTC, datetime

from bastion.config.schema import (
    BudgetRule,
    CostConfig,
    PermissionRule,
    PolicyConfig,
    RateLimitRule,
)
from bastion.policy.engine import PolicyEngine
from bastion.policy.permissions import PermissionChecker


class _FakeClock:
    """Deterministic clock for rate-limit tests."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _FakeUTC:
    """Deterministic UTC clock for budget-window tests."""

    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now


def _utc(year: int, month: int, day: int) -> datetime:
    return datetime(year, month, day, tzinfo=UTC)


def _checker(rules: list[tuple[str, str]], default: str = "allow") -> PermissionChecker:
    compiled = [PermissionRule(tool=tool, action=action) for tool, action in rules]
    return PermissionChecker(compiled, default)


def test_default_allow_when_no_rule_matches() -> None:
    assert _checker([]).check("anything").allowed


def test_default_deny_when_no_rule_matches() -> None:
    assert not _checker([], default="deny").check("anything").allowed


def test_exact_allow_rule_under_default_deny() -> None:
    assert _checker([("echo", "allow")], default="deny").check("echo").allowed


def test_deny_rule_blocks_a_tool() -> None:
    assert not _checker([("echo", "deny")]).check("echo").allowed


def test_glob_rule_matches_by_prefix() -> None:
    checker = _checker([("files_*", "deny")])
    assert not checker.check("files_read").allowed
    assert checker.check("search_web").allowed


def test_most_specific_rule_wins() -> None:
    checker = _checker([("files_*", "allow"), ("files_delete_*", "deny")])
    assert checker.check("files_read_file").allowed
    assert not checker.check("files_delete_file").allowed


def test_most_specific_wins_regardless_of_order() -> None:
    checker = _checker([("files_delete_*", "deny"), ("files_*", "allow")])
    assert not checker.check("files_delete_file").allowed


def test_decision_reason_names_the_matched_rule() -> None:
    assert "files_*" in _checker([("files_*", "deny")]).check("files_x").reason


def test_engine_allows_and_denies_per_policy() -> None:
    engine = PolicyEngine(
        PolicyConfig(default="deny", permissions=[PermissionRule(tool="echo", action="allow")])
    )
    assert engine.check("echo").allowed
    assert not engine.check("add").allowed


# ------------- rate-limit integration -------------


def test_engine_blocks_when_rate_limited() -> None:
    config = PolicyConfig(
        rate_limits=[RateLimitRule(name="cap", scope="global", max_per_minute=60, burst=1)]
    )
    engine = PolicyEngine(config, clock=_FakeClock())

    decision = engine.check("echo")
    assert decision.allowed
    engine.reserve("echo")

    decision = engine.check("echo")
    assert not decision.allowed
    assert "cap" in decision.reason


def test_engine_check_does_not_consume_rate_limit() -> None:
    config = PolicyConfig(
        rate_limits=[RateLimitRule(name="cap", scope="global", max_per_minute=60, burst=1)]
    )
    engine = PolicyEngine(config, clock=_FakeClock())

    for _ in range(5):
        assert engine.check("echo").allowed
    engine.reserve("echo")
    assert not engine.check("echo").allowed


def test_engine_permission_deny_takes_precedence_over_rate_limit() -> None:
    config = PolicyConfig(
        default="deny",
        rate_limits=[RateLimitRule(name="cap", scope="global", max_per_minute=60, burst=1)],
    )
    engine = PolicyEngine(config, clock=_FakeClock())

    decision = engine.check("blocked")
    assert not decision.allowed
    # Reason should come from the permission check, not the rate limit.
    assert "default" in decision.reason


def test_engine_rate_limit_refills_over_time() -> None:
    clock = _FakeClock()
    config = PolicyConfig(
        rate_limits=[RateLimitRule(name="cap", scope="global", max_per_minute=60, burst=1)]
    )
    engine = PolicyEngine(config, clock=clock)

    assert engine.check("echo").allowed
    engine.reserve("echo")
    assert not engine.check("echo").allowed

    clock.advance(2)
    assert engine.check("echo").allowed


# ------------- budget integration -------------


def test_engine_blocks_when_over_budget() -> None:
    config = PolicyConfig(
        budgets=[BudgetRule(name="cap", per="day", max_calls=1)],
        budget_checkpoint=None,
    )
    engine = PolicyEngine(config, now=_FakeUTC(_utc(2026, 5, 19)))

    assert engine.check("echo").allowed
    engine.reserve("echo")
    decision = engine.check("echo")
    assert not decision.allowed
    assert "cap" in decision.reason


def test_engine_uses_cost_when_charging_budget() -> None:
    cost = CostConfig(per_tool={"expensive": 0.5})
    config = PolicyConfig(
        budgets=[BudgetRule(name="cost-cap", per="day", max_cost=1.0)],
        budget_checkpoint=None,
    )
    engine = PolicyEngine(config, cost=cost, now=_FakeUTC(_utc(2026, 5, 19)))

    engine.reserve("expensive")
    engine.reserve("expensive")  # cumulative cost now 1.0
    decision = engine.check("expensive")  # would push over 1.0
    assert not decision.allowed
    assert "cost-cap" in decision.reason


def test_engine_permission_deny_takes_precedence_over_budget() -> None:
    config = PolicyConfig(
        default="deny",
        budgets=[BudgetRule(name="cap", per="day", max_calls=1)],
        budget_checkpoint=None,
    )
    engine = PolicyEngine(config, now=_FakeUTC(_utc(2026, 5, 19)))

    decision = engine.check("blocked")
    assert not decision.allowed
    assert "default" in decision.reason

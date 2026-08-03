"""Unit tests for the policy engine — permission rules and decisions."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from bastion.config.schema import (
    BudgetRule,
    CostConfig,
    GuardRule,
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


# ------------- guard integration -------------


def test_engine_blocks_when_guard_matches() -> None:
    config = PolicyConfig(
        guards=[GuardRule(name="no-rm-rf", arg="$.command", pattern=r"rm\s+-rf")],
    )
    engine = PolicyEngine(config)

    assert engine.check("shell", {"command": "ls -la"}).allowed
    decision = engine.check("shell", {"command": "rm -rf /"})
    assert not decision.allowed
    assert "no-rm-rf" in decision.reason


def test_engine_check_without_arguments_skips_guards() -> None:
    """Calling check(tool) with no arguments skips guard evaluation."""
    config = PolicyConfig(
        guards=[GuardRule(name="any", arg="$.x", pattern=".*")],
    )
    engine = PolicyEngine(config)
    assert engine.check("any-tool").allowed


def test_engine_redact_arguments_delegates_to_guard_engine() -> None:
    config = PolicyConfig(
        guards=[GuardRule(name="redact", arg="$.token", pattern=".+", action="redact")],
    )
    engine = PolicyEngine(config)
    redacted = engine.redact_arguments("auth", {"token": "secret", "user": "a"})
    assert redacted == {"token": "***", "user": "a"}


def test_engine_permission_deny_takes_precedence_over_guard() -> None:
    config = PolicyConfig(
        default="deny",
        guards=[GuardRule(name="x", arg="$.y", pattern=".+")],
    )
    engine = PolicyEngine(config)
    decision = engine.check("blocked", {"y": "anything"})
    assert not decision.allowed
    assert "default" in decision.reason


# ------------- explain is read-only -------------


def test_explain_does_not_consume_rate_limit_tokens() -> None:
    """Explaining a call must not spend the budget it is reporting on.

    Driven against one engine on purpose: each CLI invocation builds a fresh
    engine, so consumption could never show up across separate `bastion explain`
    runs however many were made.
    """
    policy = PolicyConfig.model_validate(
        {"rate_limits": [{"name": "cap", "scope": "global", "max_per_minute": 60, "burst": 3}]}
    )
    engine = PolicyEngine(policy)

    for _ in range(10):
        engine.explain("echo")

    assert engine.check("echo").allowed
    headroom = engine.explain("echo").steps[2].detail
    assert headroom.startswith("3.0 of 3")


def test_explain_does_not_advance_budgets() -> None:
    policy = PolicyConfig.model_validate(
        {
            "budgets": [{"name": "cap", "scope": "global", "per": "hour", "max_calls": 2}],
            "budget_checkpoint": None,
        }
    )
    engine = PolicyEngine(policy)

    for _ in range(10):
        engine.explain("echo")

    assert engine.check("echo").allowed
    assert "0/2 calls" in engine.explain("echo").steps[-1].detail


def test_check_does_not_consume_either() -> None:
    policy = PolicyConfig.model_validate(
        {"rate_limits": [{"name": "cap", "scope": "global", "max_per_minute": 60, "burst": 2}]}
    )
    engine = PolicyEngine(policy)

    for _ in range(5):
        assert engine.check("echo").allowed  # peek only

    engine.reserve("echo")
    engine.reserve("echo")
    assert not engine.check("echo").allowed  # now the bucket really is empty


# ------------- which rule wins when several match -------------


def _permission(rules: list[dict[str, str]], tool: str) -> bool:
    checker = PermissionChecker([PermissionRule.model_validate(r) for r in rules], "allow")
    return checker.check(tool).allowed


def test_deny_wins_a_tie_against_an_equally_specific_allow() -> None:
    """An ambiguous security rule should read the restrictive way."""
    rules = [{"tool": "a_*_xyz", "action": "allow"}, {"tool": "*_b_xyz", "action": "deny"}]
    assert not _permission(rules, "a_b_xyz")


def test_deny_wins_the_tie_regardless_of_order() -> None:
    rules = [{"tool": "*_b_xyz", "action": "deny"}, {"tool": "a_*_xyz", "action": "allow"}]
    assert not _permission(rules, "a_b_xyz")


def test_a_more_specific_allow_still_beats_a_broader_deny() -> None:
    """Deny only wins ties; it does not override a genuinely narrower rule."""
    rules = [{"tool": "*", "action": "deny"}, {"tool": "files_read_*", "action": "allow"}]
    assert _permission(rules, "files_read_file")
    assert not _permission(rules, "files_write_file")


def test_rules_that_agree_name_the_first_one() -> None:
    checker = PermissionChecker(
        [
            PermissionRule(tool="delete_thing", action="deny"),
            PermissionRule(tool="delete_*", action="deny"),
        ],
        "allow",
    )
    assert "delete_thing" in checker.check("delete_thing").reason


def test_a_config_cannot_both_allow_and_deny_the_same_pattern() -> None:
    """One of the two lines would silently do nothing — often the deny."""
    with pytest.raises(ValidationError, match="allow and deny the same pattern"):
        PolicyConfig.model_validate(
            {
                "permissions": [
                    {"tool": "payments_*", "action": "allow"},
                    {"tool": "payments_*", "action": "deny"},
                ]
            }
        )


def test_repeating_a_rule_with_the_same_action_is_fine() -> None:
    policy = PolicyConfig.model_validate(
        {"permissions": [{"tool": "x", "action": "deny"}, {"tool": "x", "action": "deny"}]}
    )
    assert len(policy.permissions) == 2

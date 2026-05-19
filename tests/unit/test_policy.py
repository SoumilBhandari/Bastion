"""Unit tests for the policy engine — permission rules and decisions."""

from bastion.config.schema import PermissionRule, PolicyConfig, RateLimitRule
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

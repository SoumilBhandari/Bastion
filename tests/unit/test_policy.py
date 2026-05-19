"""Unit tests for the policy engine — permission rules and decisions."""

from bastion.config.schema import PermissionRule, PolicyConfig
from bastion.policy.engine import PolicyEngine
from bastion.policy.permissions import PermissionChecker


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

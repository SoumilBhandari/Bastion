"""Unit tests for argument guards."""

from __future__ import annotations

from typing import Literal

from bastion.config.schema import GuardRule
from bastion.policy.guards import GuardEngine


def _guard(
    name: str,
    *,
    arg: str,
    pattern: str,
    match: str = "*",
    action: Literal["block", "redact"] = "block",
) -> GuardRule:
    return GuardRule(name=name, match=match, arg=arg, pattern=pattern, action=action)


def test_empty_engine_always_allows() -> None:
    engine = GuardEngine([])
    ok, reason = engine.check_blocking("anything", {"foo": "bar"})
    assert ok
    assert reason is None


def test_block_guard_matches_regex_in_argument() -> None:
    engine = GuardEngine([_guard("no-rm-rf", arg="$.command", pattern=r"rm\s+-rf")])
    ok, reason = engine.check_blocking("shell", {"command": "rm -rf /"})
    assert not ok
    assert reason is not None and "no-rm-rf" in reason


def test_block_guard_allows_non_matching_value() -> None:
    engine = GuardEngine([_guard("no-rm-rf", arg="$.command", pattern=r"rm\s+-rf")])
    ok, reason = engine.check_blocking("shell", {"command": "ls -la"})
    assert ok
    assert reason is None


def test_tool_glob_scopes_a_guard() -> None:
    engine = GuardEngine([_guard("files-only", match="files_*", arg="$.path", pattern="secret")])
    ok, _ = engine.check_blocking("search_web", {"path": "secret-stuff"})
    assert ok  # tool doesn't match the glob
    ok2, reason = engine.check_blocking("files_read", {"path": "secret-stuff"})
    assert not ok2
    assert reason is not None and "files-only" in reason


def test_guard_follows_nested_jsonpath() -> None:
    engine = GuardEngine([_guard("no-bearer", arg="$.headers.Authorization", pattern="Bearer ")])
    ok, reason = engine.check_blocking("fetch", {"headers": {"Authorization": "Bearer abc.def"}})
    assert not ok
    assert reason is not None and "no-bearer" in reason


def test_guard_missing_arg_path_does_not_block() -> None:
    """When the JSONPath finds nothing, the guard cannot fire."""
    engine = GuardEngine([_guard("no-bearer", arg="$.headers.Authorization", pattern="Bearer ")])
    ok, _ = engine.check_blocking("fetch", {"headers": {}})
    assert ok


def test_redact_guards_are_skipped_by_block_check() -> None:
    """Guards with action='redact' shouldn't block the call."""
    engine = GuardEngine([_guard("redact-token", arg="$.token", pattern=".+", action="redact")])
    ok, _ = engine.check_blocking("auth", {"token": "supersecret"})
    assert ok


def test_first_matching_block_guard_wins() -> None:
    engine = GuardEngine(
        [
            _guard("first", arg="$.x", pattern="bad"),
            _guard("second", arg="$.x", pattern="bad"),
        ]
    )
    ok, reason = engine.check_blocking("any", {"x": "bad value"})
    assert not ok
    assert reason is not None and "first" in reason


def test_regex_uses_search_semantics() -> None:
    """The pattern matches anywhere in the value (regex.search, not match)."""
    engine = GuardEngine([_guard("no-token", arg="$.body", pattern="TOKEN=")])
    ok, _ = engine.check_blocking("post", {"body": "prefix TOKEN=xyz suffix"})
    assert not ok


# ------------- redaction -------------


def test_redact_returns_arguments_unchanged_when_no_rules() -> None:
    engine = GuardEngine([])
    out = engine.redact("any", {"a": 1, "b": "two"})
    assert out == {"a": 1, "b": "two"}


def test_redact_replaces_matching_value_with_stars() -> None:
    engine = GuardEngine(
        [_guard("redact-token", arg="$.token", pattern=".+", action="redact")]
    )
    out = engine.redact("auth", {"token": "supersecret", "user": "alice"})
    assert out == {"token": "***", "user": "alice"}


def test_redact_only_replaces_values_matching_pattern() -> None:
    engine = GuardEngine(
        [_guard("redact-bearer", arg="$.header", pattern="^Bearer ", action="redact")]
    )
    bearer = engine.redact("h", {"header": "Bearer abc"})
    nonmatch = engine.redact("h", {"header": "Basic abc"})
    assert bearer == {"header": "***"}
    assert nonmatch == {"header": "Basic abc"}


def test_redact_respects_tool_glob() -> None:
    engine = GuardEngine(
        [
            _guard(
                "redact-files",
                match="files_*",
                arg="$.body",
                pattern=".+",
                action="redact",
            )
        ]
    )
    files = engine.redact("files_write", {"body": "secret"})
    other = engine.redact("search_web", {"body": "secret"})
    assert files == {"body": "***"}
    assert other == {"body": "secret"}


def test_redact_follows_nested_jsonpath() -> None:
    engine = GuardEngine(
        [
            _guard(
                "redact-auth",
                arg="$.headers.Authorization",
                pattern="Bearer ",
                action="redact",
            )
        ]
    )
    out = engine.redact("fetch", {"headers": {"Authorization": "Bearer xyz", "X": "y"}})
    assert out == {"headers": {"Authorization": "***", "X": "y"}}


def test_redact_does_not_mutate_input() -> None:
    engine = GuardEngine(
        [_guard("redact-token", arg="$.token", pattern=".+", action="redact")]
    )
    original = {"token": "secret"}
    _ = engine.redact("auth", original)
    assert original == {"token": "secret"}


def test_block_guards_skipped_by_redact() -> None:
    """Block guards shouldn't affect the redacted output."""
    engine = GuardEngine(
        [_guard("block-bad", arg="$.body", pattern="bad", action="block")]
    )
    out = engine.redact("post", {"body": "bad value"})
    assert out == {"body": "bad value"}

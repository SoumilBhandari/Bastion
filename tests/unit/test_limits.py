"""Bounds on how much work one call can make Bastion do."""

from typing import Any

from bastion.audit.record import json_safe
from bastion.limits import MAX_STRUCTURE_DEPTH, TOO_DEEP
from bastion.policy.responses import _leaf_strings, _map_strings
from bastion.policy.secrets import redact_structure


def _nested(levels: int) -> dict[str, Any]:
    """A structure an upstream could simply return."""
    value: dict[str, Any] = {"leaf": "value"}
    for _ in range(levels):
        value = {"nested": value}
    return value


def test_redaction_survives_a_pathologically_nested_value() -> None:
    assert TOO_DEEP in str(redact_structure(_nested(5000)))


def test_serialisation_survives_a_pathologically_nested_value() -> None:
    assert TOO_DEEP in str(json_safe(_nested(5000)))


def test_flattening_survives_a_pathologically_nested_value() -> None:
    assert TOO_DEEP in _leaf_strings(_nested(5000))


def test_rewriting_survives_a_pathologically_nested_value() -> None:
    assert TOO_DEEP in str(_map_strings(_nested(5000), str))


def test_ordinary_nesting_is_untouched() -> None:
    """The limit is far past anything a real result reaches."""
    shallow = _nested(10)
    assert TOO_DEEP not in str(redact_structure(shallow))
    assert json_safe(shallow) == shallow
    assert _leaf_strings(shallow) == ["value"]


def test_a_secret_below_the_limit_is_still_redacted() -> None:
    buried = _nested(MAX_STRUCTURE_DEPTH - 5)
    cursor = buried
    while "nested" in cursor:
        cursor = cursor["nested"]
    cursor["password"] = "hunter2"

    assert "hunter2" not in str(redact_structure(buried))


def test_the_marker_is_conspicuous() -> None:
    """It has to be obvious that the value was never examined."""
    assert "truncated" in TOO_DEEP
    assert TOO_DEEP.startswith("<")

"""Argument guards — regex/JSONPath rules that block or redact tool arguments."""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterator, Mapping
from copy import deepcopy
from typing import Any

from jsonpath_ng import parse as parse_jsonpath

from bastion.config.schema import GuardRule

REDACTED = "***"


def _candidate_strings(value: Any) -> Iterator[str]:
    """Yield the string forms a guard pattern is tested against.

    Scalars yield ``str(value)``. Lists yield each element's candidates plus a
    space-joined form, so an argv array like ``["rm", "-rf", "/"]`` cannot
    smuggle ``rm -rf`` past a string-oriented pattern. Dicts yield each value's
    candidates recursively. ``None`` yields nothing.
    """
    if value is None:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, (int, float)):
        yield str(value)
    elif isinstance(value, list):
        parts: list[str] = []
        for element in value:
            for candidate in _candidate_strings(element):
                yield candidate
                parts.append(candidate)
        if parts:
            yield " ".join(parts)
    elif isinstance(value, dict):
        for sub in value.values():
            yield from _candidate_strings(sub)
    else:
        yield str(value)


class _CompiledGuard:
    """One guard rule with its tool glob, JSONPath, and regex pre-compiled."""

    def __init__(self, rule: GuardRule) -> None:
        self.rule = rule
        self._tool_re = re.compile(fnmatch.translate(rule.match))
        self._pattern = re.compile(rule.pattern)
        self._jsonpath = parse_jsonpath(rule.arg)

    def matches_tool(self, tool: str) -> bool:
        return self._tool_re.match(tool) is not None

    def find_values(self, arguments: Mapping[str, Any]) -> list[Any]:
        return [match.value for match in self._jsonpath.find(arguments)]

    def value_matches(self, value: Any) -> bool:
        return any(self._pattern.search(s) is not None for s in _candidate_strings(value))

    def redact_in_place(self, arguments: dict[str, Any]) -> None:
        for match in self._jsonpath.find(arguments):
            if self.value_matches(match.value):
                match.full_path.update(arguments, REDACTED)


class GuardEngine:
    """Evaluates argument guards for tool calls.

    Two operations: :meth:`check_blocking` runs the ``action='block'`` rules
    and returns whether the call is allowed, and :meth:`redact` returns a
    copy of the arguments with every ``action='redact'`` rule applied.
    """

    def __init__(self, rules: list[GuardRule]) -> None:
        self._guards = [_CompiledGuard(rule) for rule in rules]

    def check_blocking(self, tool: str, arguments: Mapping[str, Any]) -> tuple[bool, str | None]:
        """Check whether any ``action='block'`` guard matches the arguments.

        Returns ``(True, None)`` if no blocking guard fires, otherwise
        ``(False, reason)`` naming the first guard that blocked the call.
        """
        for guard in self._guards:
            if guard.rule.action != "block":
                continue
            if not guard.matches_tool(tool):
                continue
            for value in guard.find_values(arguments):
                if guard.value_matches(value):
                    return False, f"blocked by guard '{guard.rule.name}'"
        return True, None

    def redact(self, tool: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        """Return a deep-copied arguments dict with all matching redact rules applied.

        Each ``action='redact'`` guard whose tool glob matches replaces every
        value at its JSONPath that matches its regex with ``"***"``. Values
        that don't match the pattern are left untouched.
        """
        redacted: dict[str, Any] = deepcopy(dict(arguments))
        for guard in self._guards:
            if guard.rule.action != "redact":
                continue
            if not guard.matches_tool(tool):
                continue
            guard.redact_in_place(redacted)
        return redacted

"""Inspection of upstream results on the way back to the agent.

Argument guards protect the outside world from the agent. Response guards
protect the agent from the outside world: a result can carry credentials the
agent should never have seen, or text engineered to steer it.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from bastion.config.schema import ResponseConfig, ResponseGuardRule
from bastion.limits import MAX_STRUCTURE_DEPTH, TOO_DEEP
from bastion.policy.injection import find_injection
from bastion.policy.secrets import find_secrets, redact_text


@dataclass
class ResponseVerdict:
    """What should happen to one upstream result."""

    blocked_by: str | None = None
    flags: list[str] = field(default_factory=list)
    redact: bool = False
    caution: bool = False

    @property
    def allowed(self) -> bool:
        return self.blocked_by is None


class _CompiledResponseGuard:
    """One operator-supplied response rule, pre-compiled."""

    def __init__(self, rule: ResponseGuardRule) -> None:
        self.rule = rule
        self._tool = re.compile(fnmatch.translate(rule.match))
        self._pattern = re.compile(rule.pattern)

    def applies_to(self, tool: str) -> bool:
        return self._tool.match(tool) is not None

    def matches(self, text: str) -> bool:
        return self._pattern.search(text) is not None

    def redact_in(self, text: str) -> str:
        return self._pattern.sub("***", text)


class ResponseInspector:
    """Decides what to do with an upstream result, and rewrites it if needed.

    :meth:`inspect` is read-only and returns a verdict; :meth:`apply` performs
    whatever rewriting the verdict called for. Keeping them apart means the
    caller can record the verdict in the audit log even when it blocks and
    there is no result to rewrite.
    """

    def __init__(self, config: ResponseConfig) -> None:
        self._config = config
        self._guards = [_CompiledResponseGuard(rule) for rule in config.guards]
        self._secret_exempt = [
            re.compile(fnmatch.translate(pattern)) for pattern in config.allow_secrets_from
        ]

    def _redacts_secrets_for(self, tool: str) -> bool:
        if not self._config.redact_secrets:
            return False
        return not any(exempt.match(tool) for exempt in self._secret_exempt)

    @property
    def active(self) -> bool:
        """Whether anything is configured to look at results at all."""
        return bool(
            self._config.redact_secrets or self._config.detect_injection != "off" or self._guards
        )

    def inspect(self, tool: str, text: str) -> ResponseVerdict:
        """Judge one result's text without changing it."""
        verdict = ResponseVerdict()

        for guard in self._guards:
            if not guard.applies_to(tool) or not guard.matches(text):
                continue
            verdict.flags.append(f"guard:{guard.rule.name}")
            if guard.rule.action == "block":
                verdict.blocked_by = f"response guard '{guard.rule.name}'"
                return verdict
            verdict.redact = True

        if self._redacts_secrets_for(tool) and (found := find_secrets(text)):
            verdict.flags.extend(f"secret:{name}" for name in found)
            verdict.redact = True

        if self._config.detect_injection != "off" and (found := find_injection(text)):
            verdict.flags.extend(f"injection:{name}" for name in found)
            if self._config.detect_injection == "block":
                verdict.blocked_by = f"suspected prompt injection ({', '.join(found)})"
                return verdict
            verdict.caution = True

        return verdict

    def apply(self, tool: str, text: str, verdict: ResponseVerdict) -> str:
        """Rewrite one result's text according to ``verdict``."""
        if verdict.redact:
            for guard in self._guards:
                if guard.rule.action == "redact" and guard.applies_to(tool):
                    text = guard.redact_in(text)
            if self._redacts_secrets_for(tool):
                text = redact_text(text)
        return text

    def apply_structured(self, tool: str, value: Any, verdict: ResponseVerdict) -> Any:
        """Rewrite a structured result according to ``verdict``.

        Runs the same transform as :meth:`apply` over every string in the
        structure, so an operator's ``redact`` guard covers structured output
        too — previously only built-in secret detection reached it, and a rule
        written to mask something in a tool's text left it exposed in the copy
        that ``result.data`` returns.
        """
        if not verdict.redact:
            return value
        return _map_strings(value, lambda text: self.apply(tool, text, verdict))

    def text_of(self, structured: Mapping[str, Any] | None) -> str:
        """Flatten a structured result to text so the same rules can scan it."""
        if not structured:
            return ""
        return " ".join(_leaf_strings(structured))


def _map_strings(value: Any, transform: Callable[[str], str], depth: int = 0) -> Any:
    """Apply ``transform`` to every string in a nested structure."""
    if depth > MAX_STRUCTURE_DEPTH:
        return TOO_DEEP
    if isinstance(value, str):
        return transform(value)
    if isinstance(value, dict):
        return {key: _map_strings(item, transform, depth + 1) for key, item in value.items()}
    if isinstance(value, list):
        return [_map_strings(item, transform, depth + 1) for item in value]
    if isinstance(value, tuple):
        return tuple(_map_strings(item, transform, depth + 1) for item in value)
    return value


def _leaf_strings(value: Any, depth: int = 0) -> list[str]:
    if depth > MAX_STRUCTURE_DEPTH:
        return [TOO_DEEP]
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [part for item in value.values() for part in _leaf_strings(item, depth + 1)]
    if isinstance(value, (list, tuple)):
        return [part for item in value for part in _leaf_strings(item, depth + 1)]
    if value is None:
        return []
    return [str(value)]

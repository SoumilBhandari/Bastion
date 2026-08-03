"""Per-tool allow/deny permission rules."""

from __future__ import annotations

import fnmatch
import re

from bastion.config.schema import Action, PermissionRule
from bastion.policy.models import PolicyDecision

_WILDCARDS = frozenset("*?[]")


def _specificity(pattern: str) -> int:
    """Score a glob by specificity: its count of literal (non-wildcard) characters."""
    return sum(1 for char in pattern if char not in _WILDCARDS)


class _CompiledRule:
    """A permission rule with its glob pre-compiled and specificity scored."""

    def __init__(self, rule: PermissionRule, order: int) -> None:
        self.pattern = rule.tool
        self.action: Action = rule.action
        self.order = order
        self.specificity = _specificity(rule.tool)
        self._matcher = re.compile(fnmatch.translate(rule.tool))

    def matches(self, tool: str) -> bool:
        return self._matcher.match(tool) is not None


class PermissionChecker:
    """Evaluates per-tool allow/deny rules.

    When several rules match a tool, the most specific wins — most literal
    characters. When two equally specific rules disagree, ``deny`` wins: the
    tie means the config does not actually say which was meant, and the safe
    reading of an ambiguous security rule is the restrictive one. Definition
    order breaks what is left, so two rules that agree still name the first.
    When no rule matches, the configured default applies.
    """

    def __init__(self, rules: list[PermissionRule], default: Action) -> None:
        self._rules = [_CompiledRule(rule, index) for index, rule in enumerate(rules)]
        self._default: Action = default

    def check(self, tool: str) -> PolicyDecision:
        """Decide whether ``tool`` is allowed by the configured permission rules."""
        matches = [rule for rule in self._rules if rule.matches(tool)]
        if not matches:
            return PolicyDecision(
                allowed=self._default == "allow",
                reason=f"no rule matched; default is '{self._default}'",
            )
        winner = max(matches, key=_precedence)
        return PolicyDecision(
            allowed=winner.action == "allow",
            reason=f"{winner.action} by rule '{winner.pattern}'",
        )


def _precedence(rule: _CompiledRule) -> tuple[int, int, int]:
    """Sort key deciding which of several matching rules applies.

    Specificity first, then deny over allow, then definition order. The middle
    term is what keeps an operator's explicit ``deny`` from being quietly
    overruled by an equally specific ``allow`` that merely happened to be
    written first.
    """
    return (rule.specificity, 1 if rule.action == "deny" else 0, -rule.order)

"""Detection and redaction of credentials in tool arguments and results.

The audit log is a record of everything an agent did, which means it is also a
record of every secret the agent handed to a tool. Writing those out verbatim
turns a security feature into a credential file: long-lived, plaintext, easy to
overlook, and worth stealing.

These detectors are deliberately prefix-anchored on the token shapes real
issuers use, rather than guessing from entropy, because a false positive here
silently destroys evidence in an audit log. The one loose rule is the
``key = value`` assignment form, which is common enough in shell commands and
config blobs to be worth the occasional over-redaction.

Nothing here is exhaustive. It catches the credentials that leak most often; a
bespoke internal token format still needs its own ``redact`` guard.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

REDACTED = "***"

SCAN_LIMIT = 1_000_000
"""How much of a value is examined.

Every pattern is scanned across the text, so an unbounded result would let one
enormous response stall the gateway. Only a prefix is examined; anything past
the limit is passed through untouched, so a credential buried deep inside a
very large result can still reach the agent.
"""


@dataclass(frozen=True)
class SecretPattern:
    """One named credential shape."""

    name: str
    pattern: re.Pattern[str]


def _compile(name: str, expression: str) -> SecretPattern:
    return SecretPattern(name, re.compile(expression))


# Every pattern below is linear-time: bounded repetition, no nested quantifiers.
# Guard regexes come from the operator, but these run against attacker-influenced
# tool output, so a pattern that could backtrack would be a denial-of-service.
BUILTIN_SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    _compile("aws-access-key-id", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    _compile("github-token", r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b"),
    _compile("github-fine-grained-token", r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b"),
    _compile("slack-token", r"\bxox[baprse]-[A-Za-z0-9-]{10,255}\b"),
    _compile("google-api-key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    _compile("stripe-key", r"\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,255}\b"),
    _compile("anthropic-api-key", r"\bsk-ant-[A-Za-z0-9_-]{16,255}\b"),
    _compile("openai-style-api-key", r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{16,255}\b"),
    _compile("private-key-block", r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    _compile("json-web-token", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    _compile("bearer-token", r"(?i:\bbearer\s+[A-Za-z0-9._~+/=-]{16,255})"),
    _compile("basic-auth-header", r"(?i:\bbasic\s+[A-Za-z0-9+/=]{16,255})"),
    # Lookaround keeps the scheme and host readable: only "user:pass" is replaced.
    _compile("url-embedded-credentials", r"(?<=://)[^\s:/@]{1,255}:[^\s:/@]{1,255}(?=@)"),
    _compile(
        "assigned-credential",
        r"""(?ix:
        \b (?: api[_-]?key | secret[_-]?key | access[_-]?token
             | auth[_-]?token | password | passwd | credential )
        \b \s* [:=] \s* ["']? ([^\s"',;}]{8,255})
        )""",
    ),
)

SENSITIVE_KEY = re.compile(
    r"""(?ix)
    ^ (?: .*[_-] )?
    (?: password | passwd | secret | token | api[_-]?key | apikey
      | access[_-]?key | private[_-]?key | credential s? | authorization | auth )
    (?: [_-].* )? $
    """
)
"""Argument names whose value is redacted whole, whatever shape it takes.

A field literally called ``password`` holds a password. Matching on the name
catches credentials that look like nothing in particular — a short passphrase,
a numeric PIN — which no value-shaped pattern ever will.
"""


def find_secrets(text: str) -> list[str]:
    """Names of every credential shape found in ``text``, in order, without duplicates."""
    return list(_ordered_unique(_scan(text)))


def redact_text(text: str) -> str:
    """Replace every recognized credential in ``text`` with ``***``.

    For the ``key = value`` form only the value is replaced, so the log still
    shows which setting was passed.
    """
    head, tail = text[:SCAN_LIMIT], text[SCAN_LIMIT:]
    for secret in BUILTIN_SECRET_PATTERNS:
        head = secret.pattern.sub(_replacement, head)
    return head + tail


def redact_structure(value: Any) -> Any:
    """Return a copy of ``value`` with credentials redacted throughout.

    Recurses into mappings and sequences. A mapping entry whose *name* looks
    sensitive has its whole value replaced; everything else is redacted by
    content.
    """
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {
            key: (REDACTED if _is_sensitive_key(key) else redact_structure(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_structure(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_structure(item) for item in value)
    return value


def _is_sensitive_key(key: Any) -> bool:
    return isinstance(key, str) and SENSITIVE_KEY.match(key) is not None


def _replacement(match: re.Match[str]) -> str:
    if match.groups() and match.group(1) is not None:
        # Keep the surrounding "api_key=" so the log still shows what was set.
        start, end = match.span(1)
        return (
            match.group(0)[: start - match.start()]
            + REDACTED
            + match.group(0)[end - match.start() :]
        )
    return REDACTED


def _scan(text: str) -> Iterator[str]:
    window = text[:SCAN_LIMIT]
    for secret in BUILTIN_SECRET_PATTERNS:
        if secret.pattern.search(window) is not None:
            yield secret.name


def _ordered_unique(names: Iterator[str]) -> Iterator[str]:
    seen: set[str] = set()
    for name in names:
        if name not in seen:
            seen.add(name)
            yield name

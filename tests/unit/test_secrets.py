"""Unit tests for built-in credential detection and redaction."""

import pytest

from bastion.policy.secrets import REDACTED, find_secrets, redact_structure, redact_text

CREDENTIALS = [
    ("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE"),
    ("github-token", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
    ("github-fine-grained-token", "github_pat_11ABCDEFG0abcdefghijklmnop"),
    ("slack-token", "xox" "b-123456789012-abcdefghijklmno"),
    ("google-api-key", "AIza" + "SyA1234567890abcdefghijklmnopqrstuv"),  # AIza + exactly 35
    ("stripe-key", "sk" "_live_abcdefghij0123456789ABCD"),
    ("anthropic-api-key", "sk-ant-api03-abcdefghijklmnopqrst"),
    ("openai-style-api-key", "sk-proj-abcdefghijklmnopqrstuvwx"),
    ("private-key-block", "-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("bearer-token", "Bearer abcdefghijklmnopqrstuvwxyz012345"),
    ("basic-auth-header", "Basic YWxhZGRpbjpvcGVuc2VzYW1l1234"),
]

INNOCENT = [
    "Please read the file at /var/log/system.log and summarise it.",
    "SELECT id, name FROM customers WHERE created_at > '2026-01-01'",
    "git commit -m 'fix the parser'",
    "The answer is 42.",
    "https://example.com/path?page=2&sort=name",
    "def compute(values): return sum(values) / len(values)",
]


@pytest.mark.parametrize(("name", "value"), CREDENTIALS)
def test_credential_is_detected(name: str, value: str) -> None:
    assert name in find_secrets(value)


@pytest.mark.parametrize(("name", "value"), CREDENTIALS)
def test_credential_is_redacted(name: str, value: str) -> None:
    assert value not in redact_text(f"the token is {value} ok")


@pytest.mark.parametrize("text", INNOCENT)
def test_ordinary_text_is_left_alone(text: str) -> None:
    assert redact_text(text) == text
    assert find_secrets(text) == []


def test_assigned_credential_keeps_the_setting_name() -> None:
    redacted = redact_text("export API_KEY=hunter2supersecret")
    assert "API_KEY" in redacted
    assert "hunter2supersecret" not in redacted


def test_url_credentials_keep_the_scheme_and_host() -> None:
    redacted = redact_text("clone https://alice:hunter2@git.example.com/repo.git")
    assert redacted == f"clone https://{REDACTED}@git.example.com/repo.git"


def test_anthropic_key_is_not_also_reported_as_openai() -> None:
    assert find_secrets("sk-ant-api03-abcdefghijklmnopqrst") == ["anthropic-api-key"]


def test_sensitive_key_names_are_redacted_whole() -> None:
    redacted = redact_structure({"password": "short", "db_token": 12345, "note": "keep me"})
    assert redacted == {"password": REDACTED, "db_token": REDACTED, "note": "keep me"}


def test_sensitive_key_matching_is_case_insensitive() -> None:
    assert redact_structure({"API_Key": "x"}) == {"API_Key": REDACTED}


def test_ordinary_key_names_survive() -> None:
    original = {"path": "/tmp/x", "count": 3, "author": "alice"}
    assert redact_structure(original) == original


def test_redaction_recurses_into_nested_structures() -> None:
    redacted = redact_structure(
        {"outer": {"inner": ["prefix", "AKIAIOSFODNN7EXAMPLE"], "creds": {"secret": "v"}}}
    )
    assert redacted["outer"]["inner"] == ["prefix", REDACTED]
    assert redacted["outer"]["creds"]["secret"] == REDACTED


def test_redaction_catches_a_token_hidden_in_an_argv_array() -> None:
    argv = ["curl", "-H", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz"]
    assert "abcdefghijklmnopqrstuvwxyz" not in str(redact_structure({"cmd": argv}))


def test_redaction_does_not_mutate_the_input() -> None:
    original = {"password": "hunter2", "nested": {"token": "abc"}}
    redact_structure(original)
    assert original == {"password": "hunter2", "nested": {"token": "abc"}}


def test_non_string_leaves_are_preserved() -> None:
    original = {"count": 7, "ratio": 1.5, "flag": True, "nothing": None}
    assert redact_structure(original) == original


def test_enormous_text_is_skipped_rather_than_scanned() -> None:
    """A multi-megabyte result must not stall the gateway on regex scanning."""
    huge = "x" * 2_000_000
    assert redact_text(huge) == huge
    assert find_secrets(huge) == []

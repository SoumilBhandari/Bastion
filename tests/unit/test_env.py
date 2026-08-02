"""Unit tests for environment-variable interpolation in the config."""

from pathlib import Path

import pytest

from bastion.config.env import EnvError, build_environment, interpolate, read_env_file


def test_interpolates_a_plain_reference() -> None:
    assert interpolate({"url": "https://${HOST}/mcp"}, {"HOST": "api.test"}) == {
        "url": "https://api.test/mcp"
    }


def test_interpolates_nested_structures() -> None:
    document = {"upstreams": {"a": {"headers": {"Authorization": "Bearer ${TOKEN}"}}}}
    result = interpolate(document, {"TOKEN": "sk-123"})
    assert result["upstreams"]["a"]["headers"]["Authorization"] == "Bearer sk-123"


def test_interpolates_inside_lists() -> None:
    assert interpolate({"args": ["--root", "${ROOT}"]}, {"ROOT": "/data"}) == {
        "args": ["--root", "/data"]
    }


def test_leaves_non_strings_alone() -> None:
    document = {"port": 8765, "enabled": True, "ratio": 1.5, "nothing": None}
    assert interpolate(document, {}) == document


def test_mapping_keys_are_not_interpolated() -> None:
    assert interpolate({"${KEY}": "v"}, {"KEY": "expanded"}) == {"${KEY}": "v"}


def test_default_is_used_when_unset() -> None:
    assert interpolate({"a": "${NOPE:-fallback}"}, {}) == {"a": "fallback"}


def test_default_is_used_when_empty() -> None:
    assert interpolate({"a": "${EMPTY:-fallback}"}, {"EMPTY": ""}) == {"a": "fallback"}


def test_empty_default_is_allowed() -> None:
    assert interpolate({"a": "x${NOPE:-}y"}, {}) == {"a": "xy"}


def test_plain_reference_to_an_empty_variable_stays_empty() -> None:
    assert interpolate({"a": "[${EMPTY}]"}, {"EMPTY": ""}) == {"a": "[]"}


def test_doubled_dollar_escapes_the_reference() -> None:
    assert interpolate({"pattern": "$${NOT_A_VAR}"}, {}) == {"pattern": "${NOT_A_VAR}"}


def test_unset_variable_is_reported_with_its_location() -> None:
    with pytest.raises(EnvError) as excinfo:
        interpolate({"upstreams": {"gh": {"url": "${GH_URL}"}}}, {})
    assert "${GH_URL}" in str(excinfo.value)
    assert "upstreams.gh.url" in str(excinfo.value)


def test_every_unset_variable_is_reported_at_once() -> None:
    with pytest.raises(EnvError) as excinfo:
        interpolate({"a": "${ONE}", "b": "${TWO}"}, {})
    message = str(excinfo.value)
    assert "${ONE}" in message
    assert "${TWO}" in message


def test_list_locations_are_indexed() -> None:
    with pytest.raises(EnvError, match=r"args\[1\]"):
        interpolate({"args": ["ok", "${MISSING}"]}, {})


def test_multiple_references_in_one_string() -> None:
    assert interpolate({"a": "${X}:${Y}"}, {"X": "1", "Y": "2"}) == {"a": "1:2"}


def test_reads_an_env_file(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "# a comment\n"
        "TOKEN=sk-abc\n"
        "export EXPORTED=yes\n"
        'QUOTED="with spaces"\n'
        "SINGLE='single'\n"
        "TRAILING=value # trailing comment\n"
        "\n"
        "not a valid line\n",
        encoding="utf-8",
    )
    values = read_env_file(tmp_path / ".env")
    assert values == {
        "TOKEN": "sk-abc",
        "EXPORTED": "yes",
        "QUOTED": "with spaces",
        "SINGLE": "single",
        "TRAILING": "value",
    }


def test_missing_env_file_is_empty(tmp_path: Path) -> None:
    assert read_env_file(tmp_path / ".env") == {}


def test_process_environment_overrides_the_env_file(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("TOKEN=from-file\nONLY_FILE=x\n", encoding="utf-8")
    merged = build_environment(tmp_path, {"TOKEN": "from-process"})
    assert merged["TOKEN"] == "from-process"
    assert merged["ONLY_FILE"] == "x"

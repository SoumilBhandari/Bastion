"""Unit tests for the mcpwarden configuration schema and loader."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from mcpwarden.config import ConfigError, WardenConfig, find_config, load_config
from mcpwarden.config.schema import Upstream


def test_minimal_config_parses() -> None:
    config = WardenConfig.model_validate(
        {"upstreams": {"files": {"command": "npx", "args": ["-y", "server"]}}}
    )
    assert config.gateway.transport == "stdio"
    assert config.gateway.port == 8765
    assert config.upstreams["files"].transport == "stdio"
    assert config.upstreams["files"].command == "npx"


def test_gateway_settings_override() -> None:
    config = WardenConfig.model_validate(
        {
            "gateway": {"transport": "http", "port": 9000},
            "upstreams": {"a": {"command": "x"}},
        }
    )
    assert config.gateway.transport == "http"
    assert config.gateway.port == 9000


def test_http_upstream_transport_inferred() -> None:
    upstream = Upstream.model_validate({"url": "https://example.com/mcp"})
    assert upstream.transport == "http"


def test_stdio_upstream_transport_inferred() -> None:
    upstream = Upstream.model_validate({"command": "python"})
    assert upstream.transport == "stdio"


def test_upstream_requires_command_or_url() -> None:
    with pytest.raises(ValidationError, match="either 'command'"):
        Upstream.model_validate({})


def test_upstream_rejects_both_command_and_url() -> None:
    with pytest.raises(ValidationError, match="not both"):
        Upstream.model_validate({"command": "x", "url": "https://example.com"})


def test_upstream_transport_conflict_rejected() -> None:
    with pytest.raises(ValidationError, match="conflicts"):
        Upstream.model_validate({"url": "https://example.com", "transport": "stdio"})


def test_http_upstream_rejects_stdio_only_fields() -> None:
    with pytest.raises(ValidationError, match="stdio upstreams"):
        Upstream.model_validate({"url": "https://example.com", "args": ["a"]})


def test_config_requires_at_least_one_upstream() -> None:
    with pytest.raises(ValidationError):
        WardenConfig.model_validate({"upstreams": {}})


def test_unknown_top_level_key_rejected() -> None:
    with pytest.raises(ValidationError):
        WardenConfig.model_validate({"upstreams": {"a": {"command": "x"}}, "bogus": 1})


def test_invalid_upstream_name_rejected() -> None:
    with pytest.raises(ValidationError, match="invalid"):
        WardenConfig.model_validate({"upstreams": {"bad name": {"command": "x"}}})


def test_load_config_reads_a_valid_file(tmp_path: Path) -> None:
    config_file = tmp_path / "mcpwarden.yaml"
    config_file.write_text("upstreams:\n  files:\n    command: npx\n", encoding="utf-8")
    config = load_config(config_file)
    assert "files" in config.upstreams


def test_load_config_rejects_invalid_yaml(tmp_path: Path) -> None:
    config_file = tmp_path / "bad.yaml"
    config_file.write_text("upstreams: [unclosed", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_config(config_file)


def test_load_config_rejects_empty_file(tmp_path: Path) -> None:
    config_file = tmp_path / "empty.yaml"
    config_file.write_text("", encoding="utf-8")
    with pytest.raises(ConfigError, match="is empty"):
        load_config(config_file)


def test_load_config_reports_validation_errors(tmp_path: Path) -> None:
    config_file = tmp_path / "mcpwarden.yaml"
    config_file.write_text("upstreams:\n  files: {}\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="is invalid"):
        load_config(config_file)


def test_find_config_uses_explicit_path(tmp_path: Path) -> None:
    config_file = tmp_path / "custom.yaml"
    config_file.write_text("upstreams:\n  a:\n    command: x\n", encoding="utf-8")
    assert find_config(config_file) == config_file


def test_find_config_missing_explicit_path(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        find_config(tmp_path / "nope.yaml")


def test_find_config_falls_back_to_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_file = tmp_path / "mcpwarden.yaml"
    config_file.write_text("upstreams:\n  a:\n    command: x\n", encoding="utf-8")
    monkeypatch.delenv("MCPWARDEN_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    assert find_config() == config_file


def test_find_config_honors_env_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_file = tmp_path / "from-env.yaml"
    config_file.write_text("upstreams:\n  a:\n    command: x\n", encoding="utf-8")
    monkeypatch.setenv("MCPWARDEN_CONFIG", str(config_file))
    assert find_config() == config_file

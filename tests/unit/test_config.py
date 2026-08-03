"""Unit tests for the Bastion configuration schema and loader."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from bastion.config import BastionConfig, ConfigError, find_config, load_config
from bastion.config.schema import Upstream


def test_minimal_config_parses() -> None:
    config = BastionConfig.model_validate(
        {"upstreams": {"files": {"command": "npx", "args": ["-y", "server"]}}}
    )
    assert config.gateway.transport == "stdio"
    assert config.gateway.port == 8765
    assert config.upstreams["files"].transport == "stdio"
    assert config.upstreams["files"].command == "npx"


def test_gateway_settings_override() -> None:
    config = BastionConfig.model_validate(
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
        BastionConfig.model_validate({"upstreams": {}})


def test_unknown_top_level_key_rejected() -> None:
    with pytest.raises(ValidationError):
        BastionConfig.model_validate({"upstreams": {"a": {"command": "x"}}, "bogus": 1})


def test_invalid_upstream_name_rejected() -> None:
    with pytest.raises(ValidationError, match="invalid"):
        BastionConfig.model_validate({"upstreams": {"bad name": {"command": "x"}}})


def test_load_config_reads_a_valid_file(tmp_path: Path) -> None:
    config_file = tmp_path / "bastion.yaml"
    config_file.write_text("upstreams:\n  files:\n    command: npx\n", encoding="utf-8")
    config = load_config(config_file)
    assert "files" in config.upstreams


def test_load_config_anchors_relative_paths_to_the_config_file(tmp_path: Path) -> None:
    nested = tmp_path / "conf"
    nested.mkdir()
    config_file = nested / "bastion.yaml"
    config_file.write_text(
        "upstreams:\n"
        "  files:\n"
        "    command: npx\n"
        "audit:\n"
        "  path: ./logs/audit.jsonl\n"
        "policy:\n"
        "  budget_checkpoint: budgets.json\n",
        encoding="utf-8",
    )
    config = load_config(config_file)
    assert config.audit.path == nested.resolve() / "logs" / "audit.jsonl"
    assert config.policy.budget_checkpoint == nested.resolve() / "budgets.json"


def test_load_config_leaves_absolute_paths_alone(tmp_path: Path) -> None:
    # Derived from tmp_path so it is genuinely absolute on Windows too: a
    # POSIX-looking "/var/log/x" has no drive letter, so Windows treats it as
    # rooted-but-relative and anchoring correctly gives it the config's drive.
    elsewhere = tmp_path.parent / "bastion-elsewhere" / "audit.jsonl"
    config_file = tmp_path / "bastion.yaml"
    config_file.write_text(
        f"upstreams:\n  files:\n    command: npx\naudit:\n  path: {elsewhere.as_posix()}\n",
        encoding="utf-8",
    )
    assert load_config(config_file).audit.path == elsewhere


def test_load_config_keeps_a_disabled_budget_checkpoint_disabled(tmp_path: Path) -> None:
    config_file = tmp_path / "bastion.yaml"
    config_file.write_text(
        "upstreams:\n  files:\n    command: npx\npolicy:\n  budget_checkpoint: null\n",
        encoding="utf-8",
    )
    assert load_config(config_file).policy.budget_checkpoint is None


def test_load_config_expands_environment_references(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BASTION_TEST_TOKEN", "sk-secret")
    config_file = tmp_path / "bastion.yaml"
    config_file.write_text(
        "upstreams:\n"
        "  remote:\n"
        "    url: https://example.test/mcp\n"
        "    headers:\n"
        "      Authorization: Bearer ${BASTION_TEST_TOKEN}\n",
        encoding="utf-8",
    )
    config = load_config(config_file)
    assert config.upstreams["remote"].headers["Authorization"] == "Bearer sk-secret"


def test_load_config_reads_secrets_from_a_dotenv_beside_it(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("BASTION_DOTENV_TOKEN=from-dotenv\n", encoding="utf-8")
    config_file = tmp_path / "bastion.yaml"
    config_file.write_text(
        "upstreams:\n"
        "  remote:\n"
        "    url: https://example.test/mcp\n"
        "    headers:\n"
        "      Authorization: ${BASTION_DOTENV_TOKEN}\n",
        encoding="utf-8",
    )
    config = load_config(config_file)
    assert config.upstreams["remote"].headers["Authorization"] == "from-dotenv"


def test_load_config_rejects_unset_environment_references(tmp_path: Path) -> None:
    config_file = tmp_path / "bastion.yaml"
    config_file.write_text(
        "upstreams:\n  files:\n    command: ${BASTION_DEFINITELY_UNSET_VAR}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="BASTION_DEFINITELY_UNSET_VAR"):
        load_config(config_file)


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
    config_file = tmp_path / "bastion.yaml"
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
    config_file = tmp_path / "bastion.yaml"
    config_file.write_text("upstreams:\n  a:\n    command: x\n", encoding="utf-8")
    monkeypatch.delenv("BASTION_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    assert find_config() == config_file


def test_find_config_honors_env_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_file = tmp_path / "from-env.yaml"
    config_file.write_text("upstreams:\n  a:\n    command: x\n", encoding="utf-8")
    monkeypatch.setenv("BASTION_CONFIG", str(config_file))
    assert find_config() == config_file


def test_audit_config_defaults_to_enabled() -> None:
    config = BastionConfig.model_validate({"upstreams": {"a": {"command": "x"}}})
    assert config.audit.enabled is True
    assert config.audit.log_arguments is True


def test_audit_config_can_be_disabled() -> None:
    config = BastionConfig.model_validate(
        {"upstreams": {"a": {"command": "x"}}, "audit": {"enabled": False}}
    )
    assert config.audit.enabled is False


def test_audit_config_rejects_unknown_key() -> None:
    with pytest.raises(ValidationError):
        BastionConfig.model_validate({"upstreams": {"a": {"command": "x"}}, "audit": {"bogus": 1}})


def test_policy_defaults_to_allow_all() -> None:
    config = BastionConfig.model_validate({"upstreams": {"a": {"command": "x"}}})
    assert config.policy.default == "allow"
    assert config.policy.permissions == []


def test_policy_section_parses() -> None:
    config = BastionConfig.model_validate(
        {
            "upstreams": {"a": {"command": "x"}},
            "policy": {
                "default": "deny",
                "permissions": [{"tool": "files_*", "action": "allow"}],
            },
        }
    )
    assert config.policy.default == "deny"
    assert config.policy.permissions[0].tool == "files_*"
    assert config.policy.permissions[0].action == "allow"


def test_policy_rejects_invalid_action() -> None:
    with pytest.raises(ValidationError):
        BastionConfig.model_validate(
            {
                "upstreams": {"a": {"command": "x"}},
                "policy": {"permissions": [{"tool": "x", "action": "maybe"}]},
            }
        )


def test_cost_defaults_to_zero() -> None:
    config = BastionConfig.model_validate({"upstreams": {"a": {"command": "x"}}})
    assert config.cost.default_per_call == 0.0
    assert config.cost.per_tool == {}


def test_cost_section_parses() -> None:
    config = BastionConfig.model_validate(
        {
            "upstreams": {"a": {"command": "x"}},
            "cost": {"default_per_call": 0.001, "per_tool": {"search_web": 0.01}},
        }
    )
    assert config.cost.default_per_call == 0.001
    assert config.cost.per_tool == {"search_web": 0.01}


def test_cost_rejects_negative_default() -> None:
    with pytest.raises(ValidationError):
        BastionConfig.model_validate(
            {"upstreams": {"a": {"command": "x"}}, "cost": {"default_per_call": -0.01}}
        )


def test_budgets_default_to_empty() -> None:
    config = BastionConfig.model_validate({"upstreams": {"a": {"command": "x"}}})
    assert config.policy.budgets == []


def test_budgets_section_parses() -> None:
    config = BastionConfig.model_validate(
        {
            "upstreams": {"a": {"command": "x"}},
            "policy": {
                "budgets": [
                    {"name": "daily-spend", "scope": "global", "per": "day", "max_cost": 5.0},
                    {"name": "hourly-calls", "per": "hour", "max_calls": 1000},
                ]
            },
        }
    )
    assert len(config.policy.budgets) == 2
    assert config.policy.budgets[0].name == "daily-spend"
    assert config.policy.budgets[0].max_cost == 5.0
    assert config.policy.budgets[1].max_calls == 1000


def test_budget_rejects_no_cap() -> None:
    with pytest.raises(ValidationError, match="max_calls or max_cost"):
        BastionConfig.model_validate(
            {
                "upstreams": {"a": {"command": "x"}},
                "policy": {"budgets": [{"name": "empty", "per": "day"}]},
            }
        )


def test_budget_rejects_invalid_window() -> None:
    with pytest.raises(ValidationError):
        BastionConfig.model_validate(
            {
                "upstreams": {"a": {"command": "x"}},
                "policy": {"budgets": [{"name": "x", "per": "week", "max_calls": 1}]},
            }
        )


def test_budget_checkpoint_default() -> None:
    config = BastionConfig.model_validate({"upstreams": {"a": {"command": "x"}}})
    assert config.policy.budget_checkpoint == Path("bastion-budgets.json")


def test_budget_checkpoint_custom_path() -> None:
    config = BastionConfig.model_validate(
        {
            "upstreams": {"a": {"command": "x"}},
            "policy": {"budget_checkpoint": "/var/lib/bastion/budgets.json"},
        }
    )
    assert config.policy.budget_checkpoint == Path("/var/lib/bastion/budgets.json")


def test_budget_checkpoint_can_be_disabled() -> None:
    config = BastionConfig.model_validate(
        {
            "upstreams": {"a": {"command": "x"}},
            "policy": {"budget_checkpoint": None},
        }
    )
    assert config.policy.budget_checkpoint is None


def test_guards_default_to_empty() -> None:
    config = BastionConfig.model_validate({"upstreams": {"a": {"command": "x"}}})
    assert config.policy.guards == []


def test_guards_section_parses() -> None:
    config = BastionConfig.model_validate(
        {
            "upstreams": {"a": {"command": "x"}},
            "policy": {
                "guards": [
                    {
                        "name": "no-rm-rf",
                        "match": "files_*",
                        "arg": "$.command",
                        "pattern": r"rm\s+-rf",
                        "action": "block",
                    },
                    {
                        "name": "redact-tokens",
                        "arg": "$.headers.Authorization",
                        "pattern": "Bearer .+",
                        "action": "redact",
                    },
                ]
            },
        }
    )
    assert len(config.policy.guards) == 2
    assert config.policy.guards[0].name == "no-rm-rf"
    assert config.policy.guards[0].action == "block"
    assert config.policy.guards[1].action == "redact"
    assert config.policy.guards[1].match == "*"  # default


def test_guard_rejects_invalid_action() -> None:
    with pytest.raises(ValidationError):
        BastionConfig.model_validate(
            {
                "upstreams": {"a": {"command": "x"}},
                "policy": {
                    "guards": [{"name": "x", "arg": "$.a", "pattern": "y", "action": "warn"}]
                },
            }
        )


def test_a_zero_per_tool_timeout_is_rejected() -> None:
    """A 0 would fail every call to that tool instantly."""
    with pytest.raises(ValidationError):
        BastionConfig.model_validate(
            {"upstreams": {"a": {"command": "x"}}, "timeouts": {"per_tool": {"slow": 0}}}
        )


def test_a_negative_per_tool_timeout_is_rejected() -> None:
    with pytest.raises(ValidationError):
        BastionConfig.model_validate(
            {"upstreams": {"a": {"command": "x"}}, "timeouts": {"per_tool": {"slow": -5}}}
        )


def test_load_config_anchors_the_pinning_path(tmp_path: Path) -> None:
    nested = tmp_path / "conf"
    nested.mkdir()
    config_file = nested / "bastion.yaml"
    config_file.write_text(
        "upstreams:\n  a:\n    command: x\npolicy:\n  pinning:\n    path: ./pins.json\n",
        encoding="utf-8",
    )
    assert load_config(config_file).policy.pinning.path == nested.resolve() / "pins.json"

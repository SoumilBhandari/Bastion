"""End-to-end tests: a real MCP client through the gateway to real upstreams."""

import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from mcp.shared.exceptions import McpError

from bastion.config.schema import BastionConfig
from bastion.gateway import build_gateway
from tests.credentials import GITHUB_TOKEN


def _config(
    upstreams: dict[str, dict[str, Any]],
    *,
    audit_path: Path | None = None,
    policy: dict[str, Any] | None = None,
    cost: dict[str, Any] | None = None,
    timeouts: dict[str, Any] | None = None,
) -> BastionConfig:
    raw: dict[str, Any] = {"upstreams": upstreams}
    if audit_path is None:
        raw["audit"] = {"enabled": False}
    else:
        raw["audit"] = {"enabled": True, "path": str(audit_path)}
    if policy is not None:
        raw["policy"] = policy
    if cost is not None:
        raw["cost"] = cost
    if timeouts is not None:
        raw["timeouts"] = timeouts

    # These configs are validated directly rather than loaded from a file, so
    # nothing anchors their relative paths — pinning would default to
    # ./bastion-pins.json and write into whatever directory pytest ran from.
    # Pinning has its own suite; switch it off everywhere else.
    raw.setdefault("policy", {})
    raw["policy"].setdefault("pinning", {"enabled": False})
    return BastionConfig.model_validate(raw)


def _stdio(python_exe: str, sample_upstream: Path) -> dict[str, dict[str, Any]]:
    return {"sample": {"command": python_exe, "args": [str(sample_upstream)]}}


async def test_gateway_lists_upstream_tools(sample_upstream: Path, python_exe: str) -> None:
    gateway = build_gateway(_config(_stdio(python_exe, sample_upstream)))
    async with Client(gateway) as client:
        names = {tool.name for tool in await client.list_tools()}
    assert {"echo", "add", "delete_thing", "write_note"} <= names


async def test_gateway_passes_through_tool_call(sample_upstream: Path, python_exe: str) -> None:
    gateway = build_gateway(_config(_stdio(python_exe, sample_upstream)))
    async with Client(gateway) as client:
        result = await client.call_tool("echo", {"text": "through the gateway"})
    assert result.data == "through the gateway"


async def test_gateway_passes_through_typed_result(sample_upstream: Path, python_exe: str) -> None:
    gateway = build_gateway(_config(_stdio(python_exe, sample_upstream)))
    async with Client(gateway) as client:
        result = await client.call_tool("add", {"a": 2, "b": 40})
    assert result.data == 42


async def test_gateway_namespaces_multiple_upstreams(
    sample_upstream: Path, python_exe: str
) -> None:
    upstreams = {
        "alpha": {"command": python_exe, "args": [str(sample_upstream)]},
        "beta": {"command": python_exe, "args": [str(sample_upstream)]},
    }
    gateway = build_gateway(_config(upstreams))
    async with Client(gateway) as client:
        names = {tool.name for tool in await client.list_tools()}
    assert {"alpha_echo", "beta_echo"} <= names


async def test_gateway_writes_an_audit_record_per_call(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    audit_log = tmp_path / "audit.jsonl"
    gateway = build_gateway(_config(_stdio(python_exe, sample_upstream), audit_path=audit_log))
    async with Client(gateway) as client:
        await client.call_tool("echo", {"text": "hi"})
        await client.call_tool("add", {"a": 1, "b": 2})
    records = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    assert [r["tool"] for r in records] == ["echo", "add"]
    assert records[0]["arguments"] == {"text": "hi"}
    assert records[0]["outcome"] == "ok"
    assert records[0]["duration_ms"] >= 0


async def test_gateway_audit_records_a_failing_call(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    audit_log = tmp_path / "audit.jsonl"
    gateway = build_gateway(_config(_stdio(python_exe, sample_upstream), audit_path=audit_log))
    async with Client(gateway) as client:
        with pytest.raises(ToolError):
            await client.call_tool("boom", {})
    records = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 1
    assert records[0]["tool"] == "boom"
    assert records[0]["outcome"] == "error"
    assert records[0]["error"]


async def test_gateway_blocks_a_denied_tool(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    audit_log = tmp_path / "audit.jsonl"
    config = _config(
        _stdio(python_exe, sample_upstream),
        audit_path=audit_log,
        policy={"default": "allow", "permissions": [{"tool": "delete_thing", "action": "deny"}]},
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        result = await client.call_tool("echo", {"text": "allowed"})
        assert result.data == "allowed"
        with pytest.raises(ToolError):
            await client.call_tool("delete_thing", {"name": "x"})
    records = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    assert records[0]["tool"] == "echo"
    assert records[0]["outcome"] == "ok"
    assert records[1]["tool"] == "delete_thing"
    assert records[1]["outcome"] == "denied"


async def test_gateway_default_deny_blocks_unlisted_tools(
    sample_upstream: Path, python_exe: str
) -> None:
    config = _config(
        _stdio(python_exe, sample_upstream),
        policy={"default": "deny", "permissions": [{"tool": "echo", "action": "allow"}]},
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        result = await client.call_tool("echo", {"text": "explicitly allowed"})
        assert result.data == "explicitly allowed"
        with pytest.raises(ToolError):
            await client.call_tool("add", {"a": 1, "b": 1})


async def test_gateway_rate_limits_tool_calls(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    """A global rate-limit rule blocks calls past its burst budget."""
    audit_log = tmp_path / "audit.jsonl"
    config = _config(
        _stdio(python_exe, sample_upstream),
        audit_path=audit_log,
        policy={
            "rate_limits": [
                {"name": "tight-cap", "scope": "global", "max_per_minute": 1, "burst": 1}
            ]
        },
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        result = await client.call_tool("echo", {"text": "first"})
        assert result.data == "first"
        with pytest.raises(ToolError):
            await client.call_tool("echo", {"text": "second"})
    records = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 2
    assert records[0]["outcome"] == "ok"
    assert records[1]["outcome"] == "denied"
    assert records[1]["error"] and "tight-cap" in records[1]["error"]


async def test_gateway_per_tool_rate_limit_isolates_buckets(
    sample_upstream: Path, python_exe: str
) -> None:
    """A per_tool rate-limit rule keeps a separate bucket per tool name."""
    config = _config(
        _stdio(python_exe, sample_upstream),
        policy={
            "rate_limits": [
                {"name": "per-tool", "scope": "per_tool", "max_per_minute": 1, "burst": 1}
            ]
        },
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        # echo consumes its bucket
        echo_result = await client.call_tool("echo", {"text": "hi"})
        assert echo_result.data == "hi"
        with pytest.raises(ToolError):
            await client.call_tool("echo", {"text": "again"})
        # add has its own bucket and still works
        add_result = await client.call_tool("add", {"a": 1, "b": 2})
        assert add_result.data == 3


async def test_gateway_blocks_when_over_call_budget(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    """A daily call-count budget blocks calls past the cap and audits the denial."""
    audit_log = tmp_path / "audit.jsonl"
    config = _config(
        _stdio(python_exe, sample_upstream),
        audit_path=audit_log,
        policy={
            "budgets": [{"name": "daily-cap", "scope": "global", "per": "day", "max_calls": 2}],
            "budget_checkpoint": None,
        },
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        await client.call_tool("echo", {"text": "first"})
        await client.call_tool("echo", {"text": "second"})
        with pytest.raises(ToolError):
            await client.call_tool("echo", {"text": "third"})
    records = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    assert [r["outcome"] for r in records] == ["ok", "ok", "denied"]
    assert "daily-cap" in records[2]["error"]


async def test_gateway_blocks_when_over_cost_budget(sample_upstream: Path, python_exe: str) -> None:
    """A cost budget blocks the call whose cost would push it over the cap."""
    config = _config(
        _stdio(python_exe, sample_upstream),
        cost={"per_tool": {"echo": 0.4, "add": 0.4}},
        policy={
            "budgets": [{"name": "spend", "scope": "global", "per": "day", "max_cost": 1.0}],
            "budget_checkpoint": None,
        },
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        await client.call_tool("echo", {"text": "a"})  # 0.4, total 0.4
        await client.call_tool("add", {"a": 1, "b": 2})  # 0.4, total 0.8
        with pytest.raises(ToolError):
            await client.call_tool("echo", {"text": "c"})  # would push to 1.2 > 1.0


async def test_gateway_budget_survives_a_restart(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    """When checkpointing is enabled, budget counters persist across gateway rebuilds."""
    checkpoint = tmp_path / "budgets.json"
    policy = {
        "budgets": [{"name": "daily-cap", "scope": "global", "per": "day", "max_calls": 2}],
        "budget_checkpoint": str(checkpoint),
    }
    config = _config(_stdio(python_exe, sample_upstream), policy=policy)

    gateway1 = build_gateway(config)
    async with Client(gateway1) as client:
        await client.call_tool("echo", {"text": "1"})
        await client.call_tool("echo", {"text": "2"})

    # Rebuild — loads counters from disk
    gateway2 = build_gateway(config)
    async with Client(gateway2) as client:
        with pytest.raises(ToolError):
            await client.call_tool("echo", {"text": "3"})


async def test_gateway_denies_resource_read_under_default_deny(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    """A default-deny policy blocks resource reads (not just tool calls) and audits them."""
    audit_log = tmp_path / "audit.jsonl"
    config = _config(
        _stdio(python_exe, sample_upstream), audit_path=audit_log, policy={"default": "deny"}
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        with pytest.raises(McpError):
            await client.read_resource("data://secret")
    records = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    resource_records = [r for r in records if r.get("kind") == "resource"]
    assert len(resource_records) == 1
    assert resource_records[0]["outcome"] == "denied"


async def test_gateway_denies_prompt_get_under_default_deny(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    """A default-deny policy blocks prompt fetches and audits them."""
    audit_log = tmp_path / "audit.jsonl"
    config = _config(
        _stdio(python_exe, sample_upstream), audit_path=audit_log, policy={"default": "deny"}
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        with pytest.raises(McpError):
            await client.get_prompt("greeting")
    records = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    prompt_records = [r for r in records if r.get("kind") == "prompt"]
    assert len(prompt_records) == 1
    assert prompt_records[0]["outcome"] == "denied"


async def test_gateway_allows_and_audits_resource_read(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    """Under default-allow a resource read goes through and is audited with kind=resource."""
    audit_log = tmp_path / "audit.jsonl"
    config = _config(
        _stdio(python_exe, sample_upstream), audit_path=audit_log, policy={"default": "allow"}
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        resources = await client.list_resources()
        uri = str(resources[0].uri)
        result = await client.read_resource(uri)
        assert "resource-secret-value" in result[0].text
    records = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    resource_records = [r for r in records if r.get("kind") == "resource"]
    assert len(resource_records) == 1
    assert resource_records[0]["outcome"] == "ok"


async def test_gateway_blocks_call_when_guard_matches(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    """A blocking argument guard stops the call and records the denial."""
    audit_log = tmp_path / "audit.jsonl"
    config = _config(
        _stdio(python_exe, sample_upstream),
        audit_path=audit_log,
        policy={
            "guards": [
                {
                    "name": "no-secret-text",
                    "arg": "$.text",
                    "pattern": "SECRET",
                    "action": "block",
                }
            ]
        },
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        result = await client.call_tool("echo", {"text": "hello"})
        assert result.data == "hello"
        with pytest.raises(ToolError):
            await client.call_tool("echo", {"text": "SECRET payload"})
    records = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    assert [r["outcome"] for r in records] == ["ok", "denied"]
    assert "no-secret-text" in records[1]["error"]


async def test_gateway_redacts_arguments_in_audit_log(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    """A redact guard replaces matching arg values in the audit log but lets the call proceed."""
    audit_log = tmp_path / "audit.jsonl"
    config = _config(
        _stdio(python_exe, sample_upstream),
        audit_path=audit_log,
        policy={
            "guards": [
                {
                    "name": "redact-secret",
                    "arg": "$.text",
                    "pattern": "secret",
                    "action": "redact",
                }
            ]
        },
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        result = await client.call_tool("echo", {"text": "a secret payload"})
        # The tool still ran with the real argument
        assert result.data == "a secret payload"
    records = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    assert records[0]["arguments"] == {"text": "***"}
    assert records[0]["outcome"] == "ok"


# ------------- policy-filtered listings -------------


async def test_denied_tools_are_hidden_from_the_listing(
    sample_upstream: Path, python_exe: str
) -> None:
    config = _config(
        _stdio(python_exe, sample_upstream),
        policy={"default": "allow", "permissions": [{"tool": "delete_thing", "action": "deny"}]},
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        names = {tool.name for tool in await client.list_tools()}
    assert "delete_thing" not in names
    assert "echo" in names


async def test_default_deny_hides_every_tool_but_the_allowlist(
    sample_upstream: Path, python_exe: str
) -> None:
    config = _config(
        _stdio(python_exe, sample_upstream),
        policy={"default": "deny", "permissions": [{"tool": "echo", "action": "allow"}]},
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        names = {tool.name for tool in await client.list_tools()}
    assert names == {"echo"}


async def test_hidden_tools_are_still_blocked_when_called_directly(
    sample_upstream: Path, python_exe: str
) -> None:
    """Filtering is presentation; the call-time check is what enforces policy."""
    config = _config(
        _stdio(python_exe, sample_upstream),
        policy={"default": "allow", "permissions": [{"tool": "delete_thing", "action": "deny"}]},
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        with pytest.raises(ToolError, match="Bastion policy"):
            await client.call_tool("delete_thing", {"name": "x"})


async def test_listing_filter_can_be_turned_off(sample_upstream: Path, python_exe: str) -> None:
    config = _config(
        _stdio(python_exe, sample_upstream),
        policy={
            "default": "allow",
            "hide_denied": False,
            "permissions": [{"tool": "delete_thing", "action": "deny"}],
        },
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        names = {tool.name for tool in await client.list_tools()}
    assert "delete_thing" in names


async def test_denied_resources_are_hidden_from_the_listing(
    sample_upstream: Path, python_exe: str
) -> None:
    config = _config(
        _stdio(python_exe, sample_upstream),
        policy={"default": "allow", "permissions": [{"tool": "data://secret", "action": "deny"}]},
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        uris = {str(resource.uri) for resource in await client.list_resources()}
    assert "data://secret" not in uris


async def test_denied_prompts_are_hidden_from_the_listing(
    sample_upstream: Path, python_exe: str
) -> None:
    config = _config(
        _stdio(python_exe, sample_upstream),
        policy={"default": "allow", "permissions": [{"tool": "greeting", "action": "deny"}]},
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        names = {prompt.name for prompt in await client.list_prompts()}
    assert "greeting" not in names


async def test_allowed_tools_are_listed_unchanged(sample_upstream: Path, python_exe: str) -> None:
    """Filtering must not alter the tools it keeps."""
    plain = build_gateway(_config(_stdio(python_exe, sample_upstream)))
    async with Client(plain) as client:
        before = {t.name: t.description for t in await client.list_tools()}

    filtered = build_gateway(
        _config(
            _stdio(python_exe, sample_upstream),
            policy={"default": "allow", "permissions": [{"tool": "boom", "action": "deny"}]},
        )
    )
    async with Client(filtered) as client:
        after = {t.name: t.description for t in await client.list_tools()}

    assert after == {name: desc for name, desc in before.items() if name != "boom"}


# ------------- call timeouts -------------


async def test_a_hanging_tool_times_out(sample_upstream: Path, python_exe: str) -> None:
    config = _config(_stdio(python_exe, sample_upstream), timeouts={"default_seconds": 0.5})
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        with pytest.raises(ToolError, match="timed out"):
            await client.call_tool("hang", {"seconds": 30})


async def test_a_timeout_is_recorded_in_the_audit_log(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    audit_log = tmp_path / "audit.jsonl"
    config = _config(
        _stdio(python_exe, sample_upstream),
        audit_path=audit_log,
        timeouts={"default_seconds": 0.5},
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        with pytest.raises(ToolError):
            await client.call_tool("hang", {"seconds": 30})

    records = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    assert records[0]["tool"] == "hang"
    assert records[0]["outcome"] == "error"
    assert "timed out" in records[0]["error"]


async def test_a_fast_tool_is_unaffected_by_the_timeout(
    sample_upstream: Path, python_exe: str
) -> None:
    config = _config(_stdio(python_exe, sample_upstream), timeouts={"default_seconds": 10})
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        assert (await client.call_tool("echo", {"text": "quick"})).data == "quick"


async def test_a_per_tool_timeout_overrides_the_default(
    sample_upstream: Path, python_exe: str
) -> None:
    """A tool granted more time survives a default that would have killed it."""
    config = _config(
        _stdio(python_exe, sample_upstream),
        timeouts={"default_seconds": 0.2, "per_tool": {"hang": 10.0}},
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        result = await client.call_tool("hang", {"seconds": 0.5})
    assert result.data == "finally done"


async def test_timeouts_can_be_disabled(sample_upstream: Path, python_exe: str) -> None:
    config = _config(_stdio(python_exe, sample_upstream), timeouts={"default_seconds": None})
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        result = await client.call_tool("hang", {"seconds": 0.1})
    assert result.data == "finally done"


# ------------- built-in secret redaction -------------


async def test_secrets_are_redacted_from_the_audit_log(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    audit_log = tmp_path / "audit.jsonl"
    # Response redaction off, so this isolates what reaches the log.
    gateway = build_gateway(
        _config(
            _stdio(python_exe, sample_upstream),
            audit_path=audit_log,
            policy=_responses(redact_secrets=False, detect_injection="off"),
        )
    )
    token = GITHUB_TOKEN

    async with Client(gateway) as client:
        result = await client.call_tool("echo", {"text": f"token is {token}"})

    # The upstream saw the real value; only the log is redacted.
    assert token in str(result.data)
    logged = audit_log.read_text(encoding="utf-8")
    assert token not in logged
    assert "***" in logged


async def test_secret_redaction_can_be_disabled(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    audit_log = tmp_path / "audit.jsonl"
    raw = {
        "upstreams": _stdio(python_exe, sample_upstream),
        "audit": {"enabled": True, "path": str(audit_log), "redact_secrets": False},
        "policy": {"pinning": {"enabled": False}},
    }
    gateway = build_gateway(BastionConfig.model_validate(raw))
    token = GITHUB_TOKEN

    async with Client(gateway) as client:
        await client.call_tool("echo", {"text": token})

    assert token in audit_log.read_text(encoding="utf-8")


# ------------- response guards -------------


def _responses(**settings: Any) -> dict[str, Any]:
    return {"default": "allow", "responses": settings}


async def test_a_credential_in_the_result_is_redacted_before_the_agent_sees_it(
    sample_upstream: Path, python_exe: str
) -> None:
    gateway = build_gateway(
        _config(_stdio(python_exe, sample_upstream), policy=_responses(redact_secrets=True))
    )
    async with Client(gateway) as client:
        result = await client.call_tool("leak_credential", {})
    assert GITHUB_TOKEN not in str(result.content)
    assert "***" in str(result.content)


async def test_response_redaction_can_be_disabled(sample_upstream: Path, python_exe: str) -> None:
    gateway = build_gateway(
        _config(
            _stdio(python_exe, sample_upstream),
            policy=_responses(redact_secrets=False, detect_injection="off"),
        )
    )
    async with Client(gateway) as client:
        result = await client.call_tool("leak_credential", {})
    assert GITHUB_TOKEN in str(result.content)


async def test_prompt_injection_is_flagged_and_cautioned_by_default(
    sample_upstream: Path, python_exe: str
) -> None:
    gateway = build_gateway(_config(_stdio(python_exe, sample_upstream)))
    async with Client(gateway) as client:
        result = await client.call_tool("poisoned_page", {})
    text = str(result.content)
    assert "untrusted data" in text
    # The original text is still delivered — the agent is warned, not blinded.
    assert "Ignore all previous instructions" in text


async def test_prompt_injection_can_be_blocked(sample_upstream: Path, python_exe: str) -> None:
    gateway = build_gateway(
        _config(_stdio(python_exe, sample_upstream), policy=_responses(detect_injection="block"))
    )
    async with Client(gateway) as client:
        with pytest.raises(ToolError, match="withheld"):
            await client.call_tool("poisoned_page", {})


async def test_injection_detection_can_be_turned_off(
    sample_upstream: Path, python_exe: str
) -> None:
    gateway = build_gateway(
        _config(_stdio(python_exe, sample_upstream), policy=_responses(detect_injection="off"))
    )
    async with Client(gateway) as client:
        result = await client.call_tool("poisoned_page", {})
    assert "untrusted data" not in str(result.content)


async def test_response_findings_reach_the_audit_log(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    audit_log = tmp_path / "audit.jsonl"
    gateway = build_gateway(_config(_stdio(python_exe, sample_upstream), audit_path=audit_log))
    async with Client(gateway) as client:
        await client.call_tool("poisoned_page", {})

    records = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    assert any("injection:instruction-override" in (r.get("flags") or []) for r in records)


async def test_a_clean_result_is_returned_untouched(sample_upstream: Path, python_exe: str) -> None:
    gateway = build_gateway(_config(_stdio(python_exe, sample_upstream)))
    async with Client(gateway) as client:
        result = await client.call_tool("echo", {"text": "an entirely ordinary answer"})
    assert result.data == "an entirely ordinary answer"


async def test_an_operator_response_guard_can_block_a_result(
    sample_upstream: Path, python_exe: str
) -> None:
    gateway = build_gateway(
        _config(
            _stdio(python_exe, sample_upstream),
            policy=_responses(
                guards=[
                    {"name": "no-secrets-word", "pattern": "here is the key", "action": "block"}
                ]
            ),
        )
    )
    async with Client(gateway) as client:
        with pytest.raises(ToolError, match="no-secrets-word"):
            await client.call_tool("leak_credential", {})


async def test_a_vault_style_tool_can_be_exempted_from_response_redaction(
    sample_upstream: Path, python_exe: str
) -> None:
    """A tool whose whole job is returning credentials must still be able to."""
    gateway = build_gateway(
        _config(
            _stdio(python_exe, sample_upstream),
            policy=_responses(redact_secrets=True, allow_secrets_from=["leak_*"]),
        )
    )
    async with Client(gateway) as client:
        exempt = await client.call_tool("leak_credential", {})
        governed = await client.call_tool("echo", {"text": f"key {GITHUB_TOKEN[:32]}"})

    assert GITHUB_TOKEN in str(exempt.content)
    assert GITHUB_TOKEN[:32] not in str(governed.content)


async def test_the_audit_log_records_what_a_call_actually_cost(
    sample_upstream: Path, python_exe: str, tmp_path: Path
) -> None:
    audit_log = tmp_path / "audit.jsonl"
    config = _config(
        _stdio(python_exe, sample_upstream),
        audit_path=audit_log,
        policy={"default": "allow", "permissions": [{"tool": "delete_thing", "action": "deny"}]},
        cost={"default_per_call": 0.001, "per_tool": {"add": 0.25}},
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        await client.call_tool("echo", {"text": "x"})
        await client.call_tool("add", {"a": 1, "b": 1})
        with pytest.raises(ToolError):
            await client.call_tool("delete_thing", {"name": "x"})

    records = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    by_tool = {r["tool"]: r for r in records}
    assert by_tool["echo"]["cost"] == 0.001
    assert by_tool["add"]["cost"] == 0.25
    # A denied call never ran, so it was never charged.
    assert by_tool["delete_thing"]["cost"] is None


async def test_a_hanging_resource_read_times_out(sample_upstream: Path, python_exe: str) -> None:
    """The timeout covers resources too, not only tool calls."""
    config = _config(_stdio(python_exe, sample_upstream), timeouts={"default_seconds": 0.5})
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        # A resource that exists and returns promptly still works under the cap.
        assert await client.read_resource("data://secret")


async def test_denied_resource_templates_are_hidden(sample_upstream: Path, python_exe: str) -> None:
    config = _config(
        _stdio(python_exe, sample_upstream),
        policy={"default": "deny", "permissions": [{"tool": "echo", "action": "allow"}]},
    )
    gateway = build_gateway(config)
    async with Client(gateway) as client:
        assert await client.list_resource_templates() == []

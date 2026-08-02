import json
from pathlib import Path

from typer.testing import CliRunner

from bastion import __version__
from bastion.cli import app

runner = CliRunner()


def test_root_version_flag_prints_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output == f"bastion {__version__}\n"


def test_version_command_prints_version() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.output == f"bastion {__version__}\n"


def test_version_tracks_installed_package_metadata() -> None:
    """__version__ must derive from the installed distribution, not a hardcoded literal."""
    from importlib.metadata import version

    assert __version__ == version("bastion-mcp")


def _write_config(tmp_path: Path, audit_path: Path | None = None) -> Path:
    config = tmp_path / "bastion.yaml"
    audit_path = audit_path or (tmp_path / "audit.jsonl")
    config.write_text(
        "upstreams:\n  a:\n    command: x\n"
        "audit:\n  enabled: true\n"
        f"  path: {audit_path.as_posix()}\n",
        encoding="utf-8",
    )
    return config


def _seed_audit(audit_path: Path, records: list[dict]) -> None:
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


def test_logs_shows_records(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    config = _write_config(tmp_path, audit_path=audit)
    _seed_audit(
        audit,
        [
            {
                "tool": "alpha",
                "outcome": "ok",
                "duration_ms": 1.5,
                "timestamp": "2026-05-25T10:00:00Z",
            },
            {
                "tool": "beta",
                "outcome": "denied",
                "duration_ms": 0.5,
                "timestamp": "2026-05-25T10:00:01Z",
                "error": "boom",
            },
        ],
    )
    result = runner.invoke(app, ["logs", "--config", str(config)])
    assert result.exit_code == 0
    assert "alpha" in result.output
    assert "beta" in result.output


def test_logs_filters_by_outcome(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    config = _write_config(tmp_path, audit_path=audit)
    _seed_audit(
        audit,
        [
            {"tool": "alpha", "outcome": "ok"},
            {"tool": "betatool", "outcome": "denied"},
        ],
    )
    result = runner.invoke(app, ["logs", "--config", str(config), "--outcome", "denied"])
    assert result.exit_code == 0
    assert "betatool" in result.output
    assert "alpha" not in result.output


def test_logs_limit_keeps_only_last_n(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    config = _write_config(tmp_path, audit_path=audit)
    _seed_audit(
        audit,
        [{"tool": f"tool{i}", "outcome": "ok"} for i in range(5)],
    )
    result = runner.invoke(app, ["logs", "--config", str(config), "-n", "2"])
    assert result.exit_code == 0
    assert "tool4" in result.output
    assert "tool3" in result.output
    assert "tool0" not in result.output


def test_logs_with_no_records(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    result = runner.invoke(app, ["logs", "--config", str(config)])
    assert result.exit_code == 0
    assert "no audit records" in result.output


def test_stats_summarizes_records(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    config = _write_config(tmp_path, audit_path=audit)
    _seed_audit(
        audit,
        [
            {"tool": "echo", "outcome": "ok", "duration_ms": 1.0},
            {"tool": "echo", "outcome": "ok", "duration_ms": 2.0},
            {"tool": "delete", "outcome": "denied", "duration_ms": 0.5},
        ],
    )
    result = runner.invoke(app, ["stats", "--config", str(config)])
    assert result.exit_code == 0
    assert "3 audit records" in result.output
    assert "echo" in result.output
    assert "delete" in result.output


def test_stats_with_no_records(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    result = runner.invoke(app, ["stats", "--config", str(config)])
    assert result.exit_code == 0
    assert "no audit records" in result.output


def test_tail_prints_streamed_records(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`bastion tail` uses tail_records to stream new records; verify with a fake stream."""
    config = _write_config(tmp_path)

    def fake_stream(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        yield {
            "tool": "streamed",
            "outcome": "ok",
            "duration_ms": 1.0,
            "timestamp": "2026-05-25T10:00:00Z",
        }

    monkeypatch.setattr("bastion.cli.tail_records", fake_stream)
    result = runner.invoke(app, ["tail", "--config", str(config)])
    assert result.exit_code == 0
    assert "streamed" in result.output


def test_init_creates_starter_config(tmp_path: Path) -> None:
    import yaml

    from bastion.config.schema import BastionConfig

    target = tmp_path / "bastion.yaml"
    result = runner.invoke(app, ["init", "--path", str(target)])
    assert result.exit_code == 0
    assert "wrote" in result.output
    assert target.exists()
    # The generated config is itself a valid Bastion config
    BastionConfig.model_validate(yaml.safe_load(target.read_text(encoding="utf-8")))


def test_init_refuses_to_overwrite_existing(tmp_path: Path) -> None:
    target = tmp_path / "bastion.yaml"
    target.write_text("# existing", encoding="utf-8")
    result = runner.invoke(app, ["init", "--path", str(target)])
    assert result.exit_code != 0
    assert "already exists" in result.output
    assert target.read_text(encoding="utf-8") == "# existing"


def test_init_force_overwrites(tmp_path: Path) -> None:
    target = tmp_path / "bastion.yaml"
    target.write_text("# old", encoding="utf-8")
    result = runner.invoke(app, ["init", "--path", str(target), "--force"])
    assert result.exit_code == 0
    assert "# old" not in target.read_text(encoding="utf-8")


def test_dashboard_warns_on_non_loopback_host(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    config = _write_config(tmp_path)
    monkeypatch.setattr("bastion.cli.run_dashboard", lambda *a, **k: None)
    result = runner.invoke(app, ["dashboard", "--config", str(config), "--host", "0.0.0.0"])
    assert result.exit_code == 0
    assert "no authentication" in result.output


def test_dashboard_no_warning_on_localhost(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    config = _write_config(tmp_path)
    monkeypatch.setattr("bastion.cli.run_dashboard", lambda *a, **k: None)
    result = runner.invoke(app, ["dashboard", "--config", str(config)])
    assert result.exit_code == 0
    assert "no authentication" not in result.output


def test_run_http_warns_on_non_loopback_host(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "bastion.yaml"
    config.write_text(
        "gateway:\n  transport: http\n  host: 0.0.0.0\nupstreams:\n  a:\n    command: x\n",
        encoding="utf-8",
    )

    class _FakeGateway:
        def run(self, **_kwargs: object) -> None:
            pass

    monkeypatch.setattr("bastion.cli.build_gateway", lambda _cfg: _FakeGateway())
    result = runner.invoke(app, ["run", "--config", str(config)])
    assert result.exit_code == 0
    assert "no authentication" in result.output


# ------------- verify -------------


def _flat(text: str) -> str:
    """Collapse Rich's line wrapping so assertions can match whole phrases."""
    return " ".join(text.split())


def _seed_chained_audit(audit_path: Path, count: int = 3) -> None:
    from bastion.audit import AuditRecord, AuditWriter

    with AuditWriter(audit_path) as writer:
        for index in range(count):
            writer.write(AuditRecord(tool=f"t{index}"))


def test_verify_accepts_an_untouched_log(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    config = _write_config(tmp_path, audit_path=audit)
    _seed_chained_audit(audit)

    result = runner.invoke(app, ["verify", "--config", str(config)])

    assert result.exit_code == 0
    assert "OK" in result.output
    assert "3 records" in result.output


def test_verify_rejects_an_edited_log(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    config = _write_config(tmp_path, audit_path=audit)
    _seed_chained_audit(audit)

    lines = audit.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["tool"] = "something_else"
    lines[1] = json.dumps(tampered)
    audit.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = runner.invoke(app, ["verify", "--config", str(config)])

    assert result.exit_code == 1
    assert "FAILED" in result.output


def test_verify_reports_an_empty_log(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    config = _write_config(tmp_path, audit_path=audit)

    result = runner.invoke(app, ["verify", "--config", str(config)])

    assert result.exit_code == 0
    assert "no audit records" in result.output


def test_verify_can_span_rotated_generations(tmp_path: Path) -> None:
    from bastion.audit import AuditRecord, AuditWriter

    audit = tmp_path / "audit.jsonl"
    config = _write_config(tmp_path, audit_path=audit)
    with AuditWriter(audit, max_bytes=200, keep=3) as writer:
        for index in range(20):
            writer.write(AuditRecord(tool=f"t{index}"))

    assert audit.with_name("audit.jsonl.1").is_file()

    spanning = runner.invoke(app, ["verify", "--config", str(config), "--include-rotated"])
    assert spanning.exit_code == 0
    assert "OK" in spanning.output


# ------------- explain -------------


def _policy_config(tmp_path: Path, policy: str) -> Path:
    config = tmp_path / "bastion.yaml"
    config.write_text(
        f"upstreams:\n  a:\n    command: x\naudit:\n  enabled: false\npolicy:\n{policy}",
        encoding="utf-8",
    )
    return config


def test_explain_reports_an_allowed_tool(tmp_path: Path) -> None:
    config = _policy_config(tmp_path, "  default: allow\n")
    result = runner.invoke(app, ["explain", "echo", "--config", str(config)])

    assert result.exit_code == 0
    assert "ALLOWED" in result.output
    assert "permissions" in result.output


def test_explain_reports_a_denied_tool_and_exits_nonzero(tmp_path: Path) -> None:
    config = _policy_config(
        tmp_path, '  default: allow\n  permissions:\n    - { tool: "drop_*", action: deny }\n'
    )
    result = runner.invoke(app, ["explain", "drop_table", "--config", str(config)])

    assert result.exit_code == 1
    assert "DENIED" in result.output
    assert "drop_*" in result.output


def test_explain_shows_every_layer_not_just_the_first_denial(tmp_path: Path) -> None:
    config = _policy_config(
        tmp_path,
        "  default: deny\n"
        "  rate_limits:\n    - { name: cap, scope: global, max_per_minute: 5 }\n"
        "  budgets:\n    - { name: daily, scope: global, per: day, max_calls: 10 }\n",
    )
    result = runner.invoke(app, ["explain", "anything", "--config", str(config)])

    assert "permissions" in result.output
    assert "cap" in result.output
    assert "daily" in result.output


def test_explain_evaluates_argument_guards(tmp_path: Path) -> None:
    config = _policy_config(
        tmp_path,
        '  guards:\n    - { name: no-etc, arg: "$.path", pattern: "^/etc/", action: block }\n',
    )
    blocked = runner.invoke(
        app, ["explain", "write", "--config", str(config), "--args", '{"path": "/etc/passwd"}']
    )
    allowed = runner.invoke(
        app, ["explain", "write", "--config", str(config), "--args", '{"path": "/tmp/ok"}']
    )

    assert blocked.exit_code == 1
    assert "no-etc" in blocked.output
    assert allowed.exit_code == 0


def test_explain_skips_guards_without_args(tmp_path: Path) -> None:
    config = _policy_config(
        tmp_path,
        '  guards:\n    - { name: no-etc, arg: "$.path", pattern: "^/etc/", action: block }\n',
    )
    result = runner.invoke(app, ["explain", "write", "--config", str(config)])

    assert result.exit_code == 0
    assert "not evaluated" in result.output


def test_explain_rejects_malformed_args(tmp_path: Path) -> None:
    config = _policy_config(tmp_path, "  default: allow\n")
    result = runner.invoke(app, ["explain", "x", "--config", str(config), "--args", "{oops"])

    assert result.exit_code == 1
    assert "not valid JSON" in result.output


def test_explain_rejects_non_object_args(tmp_path: Path) -> None:
    config = _policy_config(tmp_path, "  default: allow\n")
    result = runner.invoke(app, ["explain", "x", "--config", str(config), "--args", "[1, 2]"])

    assert result.exit_code == 1
    assert "JSON object" in result.output


def test_explain_does_not_consume_rate_limit_tokens(tmp_path: Path) -> None:
    """Explaining a call must not spend the budget it is reporting on."""
    config = _policy_config(
        tmp_path,
        "  rate_limits:\n    - { name: cap, scope: global, max_per_minute: 60, burst: 3 }\n",
    )
    for _ in range(5):
        result = runner.invoke(app, ["explain", "echo", "--config", str(config)])
        assert result.exit_code == 0
    assert "3.0 of 3" in result.output


# ------------- doctor -------------


def test_doctor_flags_a_wide_open_configuration(tmp_path: Path) -> None:
    config = tmp_path / "bastion.yaml"
    config.write_text(
        "upstreams:\n  a:\n    command: /nonexistent/binary\n"
        "audit:\n  enabled: false\n"
        "policy:\n  default: allow\n  pinning:\n    enabled: false\n"
        "timeouts:\n  default_seconds: null\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["doctor", "--config", str(config)])

    assert result.exit_code == 1  # the upstream is unreachable
    assert "unreachable" in result.output
    assert "default: deny" in result.output
    assert "nothing to stop it" in result.output
    assert "pinning is off" in result.output
    assert "wedged upstream" in result.output


def test_doctor_is_quiet_about_a_sound_configuration(tmp_path: Path) -> None:
    """A tightened config draws no advice.

    The upstream is deliberately unreachable: CliRunner replaces stdio with
    objects that have no fileno(), which a real stdio transport needs. What is
    under test here is the advice, so the connection result is ignored.
    """
    config = tmp_path / "bastion.yaml"
    config.write_text(
        "upstreams:\n  a:\n    command: /nonexistent\n"
        "audit:\n  enabled: true\n  path: ./audit.jsonl\n"
        "policy:\n  default: deny\n  permissions:\n    - { tool: echo, action: allow }\n"
        "  rate_limits:\n    - { name: cap, scope: global, max_per_minute: 60 }\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["doctor", "--config", str(config)])

    assert "nothing to flag" in result.output


def test_doctor_reports_a_broken_audit_chain(tmp_path: Path) -> None:
    from bastion.audit import AuditRecord, AuditWriter

    audit = tmp_path / "audit.jsonl"
    with AuditWriter(audit) as writer:
        writer.write(AuditRecord(tool="a"))
        writer.write(AuditRecord(tool="b"))

    lines = audit.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["tool"] = "c"
    audit.write_text(lines[0] + "\n" + json.dumps(tampered) + "\n", encoding="utf-8")

    config = tmp_path / "bastion.yaml"
    config.write_text(
        f"upstreams:\n  a:\n    command: /nonexistent\naudit:\n  path: {audit.as_posix()}\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["doctor", "--config", str(config)])

    assert "chain broken" in result.output


def test_verify_rejects_a_log_whose_front_was_deleted(tmp_path: Path) -> None:
    """Removing the oldest records must not pass as OK."""
    audit = tmp_path / "audit.jsonl"
    config = _write_config(tmp_path, audit_path=audit)
    _seed_chained_audit(audit, count=4)
    lines = audit.read_text(encoding="utf-8").splitlines()[2:]
    audit.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = runner.invoke(app, ["verify", "--config", str(config)])

    assert result.exit_code == 1
    assert "removed from the front" in _flat(result.output)


def test_verify_rejects_a_laundered_prefix(tmp_path: Path) -> None:
    """Stripping hash/prev from leading records must not pass as OK."""
    audit = tmp_path / "audit.jsonl"
    config = _write_config(tmp_path, audit_path=audit)
    _seed_chained_audit(audit, count=4)

    records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    for record in records[:2]:
        del record["hash"]
        del record["prev"]
    audit.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")

    result = runner.invoke(app, ["verify", "--config", str(config)])

    assert result.exit_code == 1
    assert "chain fields were removed" in _flat(result.output)


def test_doctor_reports_a_log_whose_front_was_deleted(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    _seed_chained_audit(audit, count=4)
    lines = audit.read_text(encoding="utf-8").splitlines()[2:]
    audit.write_text("\n".join(lines) + "\n", encoding="utf-8")

    config = tmp_path / "bastion.yaml"
    config.write_text(
        f"upstreams:\n  a:\n    command: /nonexistent\naudit:\n  path: {audit.as_posix()}\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["doctor", "--config", str(config)])

    assert "removed from the front" in _flat(result.output)

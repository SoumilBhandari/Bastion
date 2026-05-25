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

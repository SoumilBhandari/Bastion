"""Unit tests for the audit-log web dashboard."""

import json
from pathlib import Path

from starlette.testclient import TestClient

from bastion.config.schema import BastionConfig
from bastion.dashboard.app import _read_audit, _summarize, build_dashboard_app


def _record(tool: str, outcome: str = "ok", duration_ms: float = 1.0) -> str:
    return json.dumps(
        {
            "call_id": "abc",
            "timestamp": "2026-05-16T12:00:00+00:00",
            "tool": tool,
            "arguments": {"x": 1},
            "outcome": outcome,
            "duration_ms": duration_ms,
            "error": None,
        }
    )


def _config(audit_path: Path) -> BastionConfig:
    return BastionConfig.model_validate(
        {
            "upstreams": {"a": {"command": "x"}},
            "audit": {"enabled": True, "path": str(audit_path)},
        }
    )


def test_read_audit_skips_blank_and_invalid_lines(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text(f"{_record('echo')}\n\nnot json\n{_record('add')}\n", encoding="utf-8")
    records = _read_audit(log)
    assert [r["tool"] for r in records] == ["echo", "add"]


def test_read_audit_missing_file_returns_empty(tmp_path: Path) -> None:
    assert _read_audit(tmp_path / "nope.jsonl") == []


def test_summarize_counts_outcomes_and_duration() -> None:
    records = [
        {"outcome": "ok", "duration_ms": 10.0},
        {"outcome": "ok", "duration_ms": 5.0},
        {"outcome": "error", "duration_ms": 2.0},
    ]
    assert _summarize(records) == {"total": 3, "ok": 2, "errors": 1, "total_ms": 17.0}


def test_dashboard_serves_index(tmp_path: Path) -> None:
    client = TestClient(build_dashboard_app(_config(tmp_path / "audit.jsonl")))
    response = client.get("/")
    assert response.status_code == 200
    assert "Bastion" in response.text


def test_dashboard_api_returns_records_newest_first(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text(f"{_record('echo')}\n{_record('boom', outcome='error')}\n", encoding="utf-8")
    client = TestClient(build_dashboard_app(_config(log)))
    data = client.get("/api/audit").json()
    assert data["summary"]["total"] == 2
    assert data["summary"]["errors"] == 1
    assert data["records"][0]["tool"] == "boom"

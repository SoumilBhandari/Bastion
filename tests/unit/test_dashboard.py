"""Unit tests for the audit-log web dashboard."""

import json
from pathlib import Path
from typing import Any

from starlette.testclient import TestClient

from bastion.audit import AuditRecord, AuditWriter
from bastion.config.schema import BastionConfig
from bastion.dashboard.app import _summarize, build_dashboard_app

TOKEN = "test-token"


def _record(tool: str, outcome: str = "ok", duration_ms: float = 1.0, **extra: Any) -> str:
    payload: dict[str, Any] = {
        "call_id": "abc",
        "timestamp": "2026-05-16T12:00:00+00:00",
        "tool": tool,
        "arguments": {"x": 1},
        "outcome": outcome,
        "duration_ms": duration_ms,
        "error": None,
    }
    payload.update(extra)
    return json.dumps(payload)


def _config(audit_path: Path) -> BastionConfig:
    return BastionConfig.model_validate(
        {
            "upstreams": {"a": {"command": "x"}},
            "audit": {"enabled": True, "path": str(audit_path)},
        }
    )


def _client(audit_path: Path, *, token: str | None = None) -> TestClient:
    return TestClient(build_dashboard_app(_config(audit_path), token=token))


# ------------- summary -------------


def test_summarize_counts_outcomes_and_duration() -> None:
    summary = _summarize(
        [
            {"outcome": "ok", "duration_ms": 10.0},
            {"outcome": "ok", "duration_ms": 5.0},
            {"outcome": "denied", "duration_ms": 1.0},
            {"outcome": "error", "duration_ms": 2.0},
        ]
    )
    assert summary["total"] == 4
    assert summary["ok"] == 2
    assert summary["denied"] == 1
    assert summary["errors"] == 1
    assert summary["total_ms"] == 18.0


def test_summarize_totals_spend() -> None:
    summary = _summarize([{"cost": 0.01}, {"cost": 0.02}, {"cost": None}])
    assert summary["spend"] == 0.03


def test_summarize_counts_flagged_calls_and_reasons() -> None:
    summary = _summarize(
        [
            {"flags": ["injection:instruction-override"]},
            {"flags": ["injection:instruction-override", "secret:github-token"]},
            {"flags": None},
        ]
    )
    assert summary["flagged"] == 2
    assert summary["top_flags"][0] == {"name": "injection:instruction-override", "count": 2}


def test_summarize_ranks_tools_by_call_count() -> None:
    summary = _summarize([{"tool": "a"}, {"tool": "a"}, {"tool": "b"}])
    assert summary["top_tools"][0] == {"name": "a", "calls": 2}


def test_summarize_tolerates_junk_numbers() -> None:
    """A hand-edited log must not take the dashboard down."""
    summary = _summarize([{"duration_ms": "not a number", "cost": {}}])
    assert summary["total_ms"] == 0.0
    assert summary["spend"] == 0.0


def test_summarize_handles_an_empty_log() -> None:
    summary = _summarize([])
    assert summary["total"] == 0
    assert summary["top_tools"] == []


# ------------- serving -------------


def test_dashboard_serves_index(tmp_path: Path) -> None:
    response = _client(tmp_path / "audit.jsonl").get("/")
    assert response.status_code == 200
    assert "Bastion" in response.text


def test_dashboard_api_returns_records_newest_first(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text(f"{_record('echo')}\n{_record('boom', outcome='error')}\n", encoding="utf-8")

    data = _client(log).get("/api/audit").json()

    assert data["summary"]["total"] == 2
    assert data["summary"]["errors"] == 1
    assert data["records"][0]["tool"] == "boom"


def test_dashboard_picks_up_appended_records(tmp_path: Path) -> None:
    """The incremental reader must not miss anything written after the first poll."""
    log = tmp_path / "audit.jsonl"
    log.write_text(f"{_record('first')}\n", encoding="utf-8")
    client = _client(log)
    assert client.get("/api/audit").json()["summary"]["total"] == 1

    with log.open("a", encoding="utf-8") as handle:
        handle.write(f"{_record('second')}\n")

    data = client.get("/api/audit").json()
    assert data["summary"]["total"] == 2
    assert data["records"][0]["tool"] == "second"


def test_dashboard_recovers_when_the_log_is_rotated(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text(f"{_record('old')}\n" * 5, encoding="utf-8")
    client = _client(log)
    assert client.get("/api/audit").json()["summary"]["total"] == 5

    log.replace(tmp_path / "audit.jsonl.1")
    log.write_text(f"{_record('fresh')}\n", encoding="utf-8")

    data = client.get("/api/audit").json()
    assert data["summary"]["total"] == 1
    assert data["records"][0]["tool"] == "fresh"


def test_dashboard_reports_a_healthy_chain(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    with AuditWriter(log) as writer:
        writer.write(AuditRecord(tool="a"))
        writer.write(AuditRecord(tool="b"))

    chain = _client(log).get("/api/audit").json()["chain"]
    assert chain["ok"]
    assert chain["checked"] == 2


def test_dashboard_reports_a_broken_chain(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    with AuditWriter(log) as writer:
        writer.write(AuditRecord(tool="a"))
        writer.write(AuditRecord(tool="b"))
    lines = log.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["tool"] = "c"
    log.write_text(lines[0] + "\n" + json.dumps(tampered) + "\n", encoding="utf-8")

    chain = _client(log).get("/api/audit").json()["chain"]
    assert not chain["ok"]
    assert chain["problem"]


# ------------- access token -------------


def test_a_token_is_required_when_one_is_set(tmp_path: Path) -> None:
    client = _client(tmp_path / "audit.jsonl", token=TOKEN)
    assert client.get("/").status_code == 401
    assert client.get("/api/audit").status_code == 401


def test_the_right_token_is_accepted(tmp_path: Path) -> None:
    client = _client(tmp_path / "audit.jsonl", token=TOKEN)
    assert client.get(f"/?t={TOKEN}").status_code == 200
    assert client.get(f"/api/audit?t={TOKEN}").status_code == 200


def test_a_wrong_token_is_rejected(tmp_path: Path) -> None:
    client = _client(tmp_path / "audit.jsonl", token=TOKEN)
    assert client.get("/api/audit?t=not-the-token").status_code == 401


def test_the_token_can_be_supplied_as_a_header(tmp_path: Path) -> None:
    client = _client(tmp_path / "audit.jsonl", token=TOKEN)
    response = client.get("/api/audit", headers={"x-bastion-token": TOKEN})
    assert response.status_code == 200


def test_a_rejected_request_leaks_no_records(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text(f"{_record('sensitive_tool')}\n", encoding="utf-8")
    response = _client(log, token=TOKEN).get("/api/audit")
    assert "sensitive_tool" not in response.text

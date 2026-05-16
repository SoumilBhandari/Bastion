"""Unit tests for the audit record and the JSON Lines writer."""

import json
from pathlib import Path

from bastion.audit import AuditRecord, AuditWriter


def test_audit_record_generates_id_and_timestamp() -> None:
    record = AuditRecord(tool="echo", arguments={"text": "hi"})
    assert record.call_id
    assert record.timestamp
    assert record.outcome == "ok"
    assert record.error is None


def test_audit_record_to_json_line_round_trips() -> None:
    record = AuditRecord(tool="echo", arguments={"text": "hi"}, duration_ms=1.5)
    line = record.to_json_line()
    assert "\n" not in line
    data = json.loads(line)
    assert data["tool"] == "echo"
    assert data["arguments"] == {"text": "hi"}
    assert data["outcome"] == "ok"
    assert data["duration_ms"] == 1.5
    assert data["error"] is None


def test_audit_record_serializes_non_json_values() -> None:
    record = AuditRecord(tool="t", arguments={"path": Path("/x")})
    data = json.loads(record.to_json_line())
    assert isinstance(data["arguments"]["path"], str)


def test_audit_writer_appends_one_line_per_record(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    writer = AuditWriter(log)
    writer.write(AuditRecord(tool="a"))
    writer.write(AuditRecord(tool="b"))
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["tool"] == "a"
    assert json.loads(lines[1])["tool"] == "b"


def test_audit_writer_creates_parent_directories(tmp_path: Path) -> None:
    log = tmp_path / "nested" / "dir" / "audit.jsonl"
    AuditWriter(log).write(AuditRecord(tool="x"))
    assert log.is_file()

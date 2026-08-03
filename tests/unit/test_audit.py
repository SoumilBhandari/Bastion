"""Unit tests for the audit record and the JSON Lines writer."""

import json
from pathlib import Path

import pytest

from bastion.audit import AuditRecord, AuditWriter, rotated_paths


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


def test_audit_writer_flushes_each_record_immediately(tmp_path: Path) -> None:
    """A crashed gateway must still leave every record it claimed to write."""
    log = tmp_path / "audit.jsonl"
    writer = AuditWriter(log)
    writer.write(AuditRecord(tool="a"))
    assert len(log.read_text(encoding="utf-8").splitlines()) == 1


def test_audit_writer_fsyncs_when_asked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Asserting the line was written proves nothing; fsync must actually be called."""
    synced: list[int] = []
    monkeypatch.setattr("bastion.audit.writer.os.fsync", synced.append)

    with AuditWriter(tmp_path / "audit.jsonl", fsync=True) as writer:
        writer.write(AuditRecord(tool="a"))
        writer.write(AuditRecord(tool="b"))

    assert len(synced) == 2


def test_audit_writer_does_not_fsync_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A disk round trip per call is opt-in."""
    synced: list[int] = []
    monkeypatch.setattr("bastion.audit.writer.os.fsync", synced.append)

    with AuditWriter(tmp_path / "audit.jsonl") as writer:
        writer.write(AuditRecord(tool="a"))

    assert synced == []


def test_audit_writer_rotates_past_the_size_limit(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    writer = AuditWriter(log, max_bytes=200, keep=3)
    for index in range(20):
        writer.write(AuditRecord(tool=f"t{index}"))
    writer.close()
    assert log.with_name("audit.jsonl.1").is_file()
    assert log.stat().st_size <= 200


def test_audit_writer_keeps_only_the_requested_generations(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    writer = AuditWriter(log, max_bytes=150, keep=2)
    for index in range(40):
        writer.write(AuditRecord(tool=f"t{index}"))
    writer.close()
    assert log.with_name("audit.jsonl.2").is_file()
    assert not log.with_name("audit.jsonl.3").exists()


def test_audit_writer_rotation_is_off_by_default(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    writer = AuditWriter(log, max_bytes=None)
    for index in range(50):
        writer.write(AuditRecord(tool=f"t{index}"))
    writer.close()
    assert not log.with_name("audit.jsonl.1").exists()


def test_rotated_paths_are_returned_oldest_first(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    for generation in (1, 2, 3):
        log.with_name(f"audit.jsonl.{generation}").write_text("{}\n", encoding="utf-8")
    assert [p.name for p in rotated_paths(log)] == [
        "audit.jsonl.3",
        "audit.jsonl.2",
        "audit.jsonl.1",
    ]


def test_rotated_paths_is_empty_when_nothing_rotated(tmp_path: Path) -> None:
    assert rotated_paths(tmp_path / "audit.jsonl") == []


def test_a_rotation_that_cannot_rename_does_not_fail_the_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Windows refuses to rename a file another process has open — a reader does."""
    log = tmp_path / "audit.jsonl"
    writer = AuditWriter(log, max_bytes=150, keep=2)

    def refuse(*_: object, **__: object) -> None:
        raise PermissionError(13, "used by another process")

    monkeypatch.setattr("bastion.audit.writer._rotate", refuse)
    for index in range(20):
        writer.write(AuditRecord(tool=f"t{index}"))  # must not raise
    writer.close()

    assert len(log.read_text(encoding="utf-8").splitlines()) == 20


# ------------- values JSON cannot represent -------------


def test_a_non_finite_argument_is_written_as_valid_json(tmp_path: Path) -> None:
    """json.dumps emits bare Infinity, which no conforming parser accepts."""
    log = tmp_path / "audit.jsonl"
    with AuditWriter(log) as writer:
        writer.write(AuditRecord(tool="calc", arguments={"x": float("inf")}))

    def reject_constants(name: str) -> object:
        raise AssertionError(f"non-JSON constant in the log: {name}")

    parsed = json.loads(log.read_text(encoding="utf-8"), parse_constant=reject_constants)
    assert parsed["arguments"]["x"] == "inf"


def test_non_finite_values_survive_the_hash_chain(tmp_path: Path) -> None:
    """Sanitising before hashing keeps the written line and the hashed content the same."""
    from bastion.audit import read_records, verify_records

    log = tmp_path / "audit.jsonl"
    with AuditWriter(log) as writer:
        writer.write(AuditRecord(tool="a", arguments={"x": float("nan")}))
        writer.write(AuditRecord(tool="b", arguments={"y": float("-inf")}))

    report = verify_records(read_records(log))
    assert report.ok
    assert report.checked == 2


def test_json_safe_leaves_ordinary_values_alone() -> None:
    from bastion.audit.record import json_safe

    original = {"a": 1, "b": 1.5, "c": "text", "d": None, "e": [1, {"f": True}]}
    assert json_safe(original) == original


def test_json_safe_recurses() -> None:
    from bastion.audit.record import json_safe

    assert json_safe({"a": [{"b": float("inf")}]}) == {"a": [{"b": "inf"}]}

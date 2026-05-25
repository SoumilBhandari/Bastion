"""Unit tests for the audit log reader."""

from __future__ import annotations

from pathlib import Path

from bastion.audit import AuditRecord, AuditWriter, iter_records, read_records


def test_read_records_handles_missing_file(tmp_path: Path) -> None:
    assert read_records(tmp_path / "nothing.jsonl") == []


def test_read_records_returns_empty_for_empty_file(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text("", encoding="utf-8")
    assert read_records(log) == []


def test_read_records_round_trips_writer_output(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    writer = AuditWriter(log)
    writer.write(AuditRecord(tool="echo", arguments={"text": "hi"}))
    writer.write(AuditRecord(tool="add", outcome="ok"))

    records = read_records(log)
    assert [r["tool"] for r in records] == ["echo", "add"]
    assert records[0]["arguments"] == {"text": "hi"}
    assert records[1]["outcome"] == "ok"


def test_read_records_skips_blank_lines(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text(
        '{"tool":"a","outcome":"ok"}\n\n   \n{"tool":"b","outcome":"ok"}\n',
        encoding="utf-8",
    )
    assert [r["tool"] for r in read_records(log)] == ["a", "b"]


def test_read_records_skips_malformed_lines(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text(
        '{"tool":"a","outcome":"ok"}\nnot json\n{"tool":"b","outcome":"ok"}\n',
        encoding="utf-8",
    )
    assert [r["tool"] for r in read_records(log)] == ["a", "b"]


def test_read_records_skips_non_object_json(tmp_path: Path) -> None:
    """A JSON value that isn't an object (e.g. a bare string or list) is skipped."""
    log = tmp_path / "audit.jsonl"
    log.write_text(
        '{"tool":"a","outcome":"ok"}\n"just a string"\n[1,2,3]\n{"tool":"b","outcome":"ok"}\n',
        encoding="utf-8",
    )
    assert [r["tool"] for r in read_records(log)] == ["a", "b"]


def test_iter_records_is_lazy(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text(
        "\n".join(f'{{"tool":"t{i}","outcome":"ok"}}' for i in range(5)) + "\n",
        encoding="utf-8",
    )
    first_three = []
    for record in iter_records(log):
        first_three.append(record["tool"])
        if len(first_three) == 3:
            break
    assert first_three == ["t0", "t1", "t2"]

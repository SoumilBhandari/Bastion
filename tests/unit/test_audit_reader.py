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


# ------------- tail_records -------------


def test_tail_records_emits_new_appends(tmp_path: Path) -> None:
    from bastion.audit import tail_records

    log = tmp_path / "audit.jsonl"
    log.write_text('{"tool":"old","outcome":"ok"}\n', encoding="utf-8")

    seen: list[str] = []
    appended = [False]

    def fake_sleep(_: float) -> None:
        if not appended[0]:
            with log.open("a", encoding="utf-8") as h:
                h.write('{"tool":"new","outcome":"ok"}\n')
            appended[0] = True

    def stop_after_one() -> bool:
        return len(seen) >= 1

    for record in tail_records(log, sleep=fake_sleep, should_stop=stop_after_one):
        seen.append(record["tool"])

    assert seen == ["new"]


def test_tail_records_waits_for_file_to_exist(tmp_path: Path) -> None:
    from bastion.audit import tail_records

    log = tmp_path / "audit.jsonl"  # does not exist yet
    seen: list[str] = []
    created = [False]

    def fake_sleep(_: float) -> None:
        if not created[0]:
            log.write_text("", encoding="utf-8")
            created[0] = True
        elif len(seen) == 0:
            with log.open("a", encoding="utf-8") as h:
                h.write('{"tool":"hello","outcome":"ok"}\n')

    def stop_when_seen() -> bool:
        return len(seen) >= 1

    for record in tail_records(log, sleep=fake_sleep, should_stop=stop_when_seen):
        seen.append(record["tool"])

    assert seen == ["hello"]


def test_tail_records_follows_the_log_across_a_rotation(tmp_path: Path) -> None:
    """After rotation the saved offset points past a smaller file; keep following."""
    from bastion.audit import tail_records

    log = tmp_path / "audit.jsonl"
    log.write_text('{"tool":"a","outcome":"ok"}\n' * 20, encoding="utf-8")

    seen: list[str] = []
    rotated = [False]

    def fake_sleep(_: float) -> None:
        if not rotated[0]:
            log.replace(tmp_path / "audit.jsonl.1")
            log.write_text('{"tool":"after_rotation","outcome":"ok"}\n', encoding="utf-8")
            rotated[0] = True

    def stop_when_seen() -> bool:
        return len(seen) >= 1

    for record in tail_records(log, sleep=fake_sleep, should_stop=stop_when_seen):
        seen.append(record["tool"])

    assert seen == ["after_rotation"]


def test_tail_records_respects_should_stop_immediately(tmp_path: Path) -> None:
    from bastion.audit import tail_records

    log = tmp_path / "audit.jsonl"
    log.write_text("", encoding="utf-8")
    assert list(tail_records(log, sleep=lambda _: None, should_stop=lambda: True)) == []

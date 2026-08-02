"""Unit tests for the tamper-evident audit hash chain."""

import json
from itertools import pairwise
from pathlib import Path
from typing import Any

from bastion.audit import AuditRecord, AuditWriter
from bastion.audit.chain import GENESIS, record_hash, verify_records


def _write(path: Path, count: int, **kwargs: Any) -> AuditWriter:
    writer = AuditWriter(path, **kwargs)
    for index in range(count):
        writer.write(AuditRecord(tool=f"tool_{index}", arguments={"i": index}))
    writer.close()
    return writer


def _read(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_first_record_links_to_genesis(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    _write(log, 1)
    assert _read(log)[0]["prev"] == GENESIS


def test_each_record_links_to_the_previous(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    _write(log, 4)
    records = _read(log)
    for earlier, later in pairwise(records):
        assert later["prev"] == earlier["hash"]


def test_an_untouched_log_verifies(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    _write(log, 5)
    report = verify_records(_read(log))
    assert report.ok
    assert report.checked == 5
    assert report.starts_at_genesis


def test_editing_a_record_is_detected(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    _write(log, 5)
    records = _read(log)
    records[2]["outcome"] = "ok" if records[2]["outcome"] != "ok" else "denied"
    report = verify_records(records)
    assert not report.ok
    assert report.breaks[0].index == 2
    assert "altered" in report.breaks[0].reason


def test_editing_an_argument_is_detected(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    _write(log, 3)
    records = _read(log)
    records[1]["arguments"] = {"i": 999}
    assert not verify_records(records).ok


def test_deleting_a_record_is_detected(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    _write(log, 5)
    records = _read(log)
    del records[2]
    report = verify_records(records)
    assert not report.ok
    assert report.breaks[0].index == 2
    assert "expected prev" in report.breaks[0].reason


def test_reordering_records_is_detected(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    _write(log, 4)
    records = _read(log)
    records[1], records[2] = records[2], records[1]
    assert not verify_records(records).ok


def test_appending_a_forged_record_is_detected(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    _write(log, 2)
    records = _read(log)
    forged = dict(records[-1])
    forged["tool"] = "exfiltrate"
    records.append(forged)
    assert not verify_records(records).ok


def test_truncating_the_chain_is_detected(tmp_path: Path) -> None:
    """Dropping the hash from a later record cannot silently un-chain the log."""
    log = tmp_path / "audit.jsonl"
    _write(log, 3)
    records = _read(log)
    del records[2]["hash"]
    report = verify_records(records)
    assert not report.ok
    assert "truncated" in report.breaks[0].reason


def test_records_written_before_chaining_are_not_failures(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    _write(log, 2, hash_chain=False)
    report = verify_records(_read(log))
    assert report.ok
    assert report.unchained == 2
    assert report.checked == 0


def test_verification_is_empty_for_no_records() -> None:
    report = verify_records([])
    assert report.ok
    assert report.checked == 0
    assert report.head is None


def test_a_reopened_writer_continues_the_chain(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    _write(log, 2)
    _write(log, 2)
    report = verify_records(_read(log))
    assert report.ok
    assert report.checked == 4


def test_head_matches_the_last_records_hash(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    writer = _write(log, 3)
    assert writer.head == _read(log)[-1]["hash"]


def test_hash_covers_the_previous_hash() -> None:
    payload = {"tool": "echo", "outcome": "ok"}
    assert record_hash(payload, "a" * 64) != record_hash(payload, "b" * 64)


def test_hash_ignores_key_order() -> None:
    assert record_hash({"a": 1, "b": 2}, GENESIS) == record_hash({"b": 2, "a": 1}, GENESIS)


def test_chaining_can_be_disabled(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    _write(log, 1, hash_chain=False)
    assert "hash" not in _read(log)[0]

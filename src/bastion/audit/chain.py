"""Tamper-evident hash chaining for the audit log.

An audit log that anyone can quietly edit is a weak audit log. Each record
carries the hash of the record before it, so the file is a chain: changing,
reordering, or removing any record breaks every link after it, and the break
cannot be repaired without rewriting the entire remaining log.

This detects tampering; it does not prevent it. An attacker who can rewrite the
whole file can produce a valid chain. To make that impossible, copy the newest
record's hash somewhere the attacker cannot reach — another host, a printout, a
transparency log — and check it against ``bastion verify``.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

GENESIS = "0" * 64
"""The ``prev`` value of the first record in a chain."""

HASH_FIELD = "hash"
PREV_FIELD = "prev"


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    """Serialize a payload deterministically, so the same record always hashes alike."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
        ensure_ascii=False,
    ).encode("utf-8")


def record_hash(payload: Mapping[str, Any], prev: str) -> str:
    """Compute a record's hash: SHA-256 over its fields plus the previous hash."""
    body = {key: value for key, value in payload.items() if key != HASH_FIELD}
    body[PREV_FIELD] = prev
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


@dataclass
class ChainBreak:
    """One place where the chain does not hold."""

    index: int
    call_id: str | None
    reason: str

    def __str__(self) -> str:
        where = f"record {self.index}"
        if self.call_id:
            where += f" (call_id {self.call_id})"
        return f"{where}: {self.reason}"


@dataclass
class ChainReport:
    """The outcome of verifying a chain."""

    checked: int = 0
    unchained: int = 0
    breaks: list[ChainBreak] = field(default_factory=list)
    head: str | None = None
    starts_at_genesis: bool = True

    @property
    def ok(self) -> bool:
        return not self.breaks


def verify_records(records: Iterable[Mapping[str, Any]]) -> ChainReport:
    """Verify that a sequence of audit records forms an unbroken hash chain.

    Records written before chaining was enabled carry no ``hash`` and are
    counted as ``unchained`` rather than reported as breaks — an older log that
    was never chained is not evidence of tampering. Once a chained record is
    seen, every record after it must also be chained.
    """
    report = ChainReport()
    expected_prev: str | None = None

    for index, record in enumerate(records):
        stored = record.get(HASH_FIELD)
        call_id = record.get("call_id")
        call_id = str(call_id) if call_id is not None else None

        if not isinstance(stored, str):
            if expected_prev is None:
                report.unchained += 1
                continue
            report.breaks.append(
                ChainBreak(index, call_id, "record is missing its hash — chain truncated here")
            )
            break

        prev = record.get(PREV_FIELD)
        prev = prev if isinstance(prev, str) else ""

        if expected_prev is None:
            report.starts_at_genesis = prev == GENESIS
            # A chain that opens mid-stream cannot legitimately sit behind
            # unchained records. When chaining is switched on, the writer starts
            # a fresh chain at genesis, so unchained history is always followed
            # by a genesis link. Anything else means the records in between were
            # chained once and had their chain fields stripped — the cheapest way
            # to rewrite a prefix of the log while the tail still verifies and
            # the head hash is unchanged.
            if report.unchained and prev != GENESIS:
                report.breaks.append(
                    ChainBreak(
                        index,
                        call_id,
                        f"{report.unchained} record(s) before this one carry no hash, but this "
                        "one continues a chain — their chain fields were removed",
                    )
                )
                break
        elif prev != expected_prev:
            report.breaks.append(
                ChainBreak(
                    index, call_id, f"expected prev {expected_prev[:12]}…, found {prev[:12]}…"
                )
            )
            break

        computed = record_hash(record, prev)
        if computed != stored:
            report.breaks.append(
                ChainBreak(
                    index, call_id, "contents do not match the recorded hash — record altered"
                )
            )
            break

        report.checked += 1
        report.head = stored
        expected_prev = stored

    return report

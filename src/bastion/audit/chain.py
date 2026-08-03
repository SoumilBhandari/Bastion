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


class ChainVerifier:
    """Verifies a chain, and can be fed the rest of it later.

    Verification is sequential, so a caller watching a growing log — the
    dashboard polls one every 1.5 seconds — can hash only what arrived since
    last time instead of the whole file again. Re-verifying from the start on
    every poll makes the cost of watching a log grow with its length, which for
    an append-only file means it gets slower forever.
    """

    def __init__(self) -> None:
        self.report = ChainReport()
        self._expected_prev: str | None = None
        self._index = 0
        self._stopped = False

    def feed(self, records: Iterable[Mapping[str, Any]]) -> ChainReport:
        """Verify further records, continuing from wherever the last call ended."""
        if self._stopped:
            return self.report
        self._verify(records)
        return self.report

    def _verify(self, records: Iterable[Mapping[str, Any]]) -> None:
        report = self.report
        expected_prev = self._expected_prev

        for record in records:
            index = self._index
            self._index += 1
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

        self._expected_prev = expected_prev
        # A break is final. Everything after the first one is unverifiable, so
        # a later feed must not quietly resume as though the chain still held.
        self._stopped = bool(report.breaks)


def verify_records(records: Iterable[Mapping[str, Any]]) -> ChainReport:
    """Verify that a sequence of audit records forms an unbroken hash chain.

    Records written before chaining was enabled carry no ``hash`` and are
    counted as ``unchained`` rather than reported as breaks — an older log that
    was never chained is not evidence of tampering. Once a chained record is
    seen, every record after it must also be chained.
    """
    return ChainVerifier().feed(records)

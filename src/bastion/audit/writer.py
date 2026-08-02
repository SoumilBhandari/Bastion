"""Append-only JSON Lines writer for audit records."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import TracebackType
from typing import IO, Any

from bastion.audit.chain import GENESIS, HASH_FIELD, PREV_FIELD, record_hash
from bastion.audit.record import AuditRecord

_TAIL_SCAN_BYTES = 256 * 1024
"""How far back to look for the last record when resuming an existing log."""


class AuditWriter:
    """Appends audit records to a JSON Lines file — one record per line.

    The file handle stays open for the process's lifetime rather than being
    reopened per record, and every record is flushed as it is written, so a
    crashed gateway still leaves a complete log up to its last call. Set
    ``fsync=True`` to also force the write out to the physical disk — that
    survives the machine losing power, at the cost of a real disk round trip
    on every call.

    With ``hash_chain`` enabled each record carries the previous record's hash,
    which makes after-the-fact edits detectable — see :mod:`bastion.audit.chain`.
    When ``max_bytes`` is set the log rotates to ``<name>.1``, ``<name>.2``, …
    keeping ``keep`` generations; the chain continues across a rotation, so the
    generations still verify as one sequence.
    """

    def __init__(
        self,
        path: Path,
        *,
        hash_chain: bool = True,
        fsync: bool = False,
        max_bytes: int | None = None,
        keep: int = 5,
    ) -> None:
        self._path = path
        self._hash_chain = hash_chain
        self._fsync = fsync
        self._max_bytes = max_bytes if max_bytes and max_bytes > 0 else None
        self._keep = max(keep, 0)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._prev = _last_hash(path) if hash_chain else GENESIS
        self._handle: IO[str] | None = None
        self._size = path.stat().st_size if path.exists() else 0

    @property
    def path(self) -> Path:
        return self._path

    @property
    def head(self) -> str:
        """The newest record's hash — the value worth anchoring outside this machine."""
        return self._prev

    def write(self, record: AuditRecord) -> None:
        """Append one audit record to the log file."""
        payload: dict[str, Any] = record.payload()
        if self._hash_chain:
            payload[PREV_FIELD] = self._prev
            payload[HASH_FIELD] = record_hash(payload, self._prev)
        line = json.dumps(payload, default=str, ensure_ascii=False) + "\n"

        handle = self._open()
        handle.write(line)
        handle.flush()
        if self._fsync:
            os.fsync(handle.fileno())

        # Advance the chain only once the record is actually written: a write
        # that raised must not leave the next record pointing at a hash that
        # never reached the file.
        if self._hash_chain:
            self._prev = str(payload[HASH_FIELD])
        self._size += len(line.encode("utf-8"))
        self._maybe_rotate()

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def __enter__(self) -> AuditWriter:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def _open(self) -> IO[str]:
        if self._handle is None:
            self._handle = self._path.open("a", encoding="utf-8")
        return self._handle

    def _maybe_rotate(self) -> None:
        if self._max_bytes is None or self._size < self._max_bytes:
            return
        self.close()
        _rotate(self._path, self._keep)
        self._size = 0
        # Recreate the active log straight away rather than on the next call, so
        # readers following the path never see it vanish between two records.
        self._open()


def _rotate(path: Path, keep: int) -> None:
    """Shift ``path`` to ``path.1``, ``path.1`` to ``path.2``, and so on."""
    if keep == 0:
        path.unlink(missing_ok=True)
        return
    path.with_name(f"{path.name}.{keep}").unlink(missing_ok=True)
    for generation in range(keep - 1, 0, -1):
        source = path.with_name(f"{path.name}.{generation}")
        if source.exists():
            source.replace(path.with_name(f"{path.name}.{generation + 1}"))
    if path.exists():
        path.replace(path.with_name(f"{path.name}.1"))


def rotated_paths(path: Path, keep: int = 64) -> list[Path]:
    """Existing rotated generations of ``path``, oldest first."""
    found = [
        candidate
        for generation in range(keep, 0, -1)
        if (candidate := path.with_name(f"{path.name}.{generation}")).exists()
    ]
    return found


def _last_hash(path: Path) -> str:
    """Read the last record's hash from an existing log, to resume its chain.

    Reads only the tail of the file, so restarting the gateway does not cost a
    full scan of a log that may be gigabytes long. A log with no usable trailing
    record — missing, empty, or never chained — starts a fresh chain at the
    genesis value.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return GENESIS
    if size == 0:
        return GENESIS

    try:
        with path.open("rb") as handle:
            handle.seek(max(0, size - _TAIL_SCAN_BYTES))
            tail = handle.read()
    except OSError:
        return GENESIS

    for raw in reversed(tail.split(b"\n")):
        line = raw.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, ValueError):
            continue
        if isinstance(value, dict) and isinstance(value.get(HASH_FIELD), str):
            return str(value[HASH_FIELD])
    return GENESIS

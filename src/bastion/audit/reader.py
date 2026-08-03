"""Reading audit JSON Lines records."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any


def parse_line(raw: bytes) -> dict[str, Any] | None:
    """Decode and parse one line, or ``None`` if it is not a usable record.

    Decoding replaces undecodable bytes rather than raising. The log is append-
    only and machine-written, but it is also a plain file on disk: a truncated
    write, a crashed process, or a stray byte from anything else leaves
    something that is not valid UTF-8. Letting that propagate meant one bad byte
    anywhere took down `bastion logs`, `stats`, `verify` and the dashboard, all
    with a raw traceback — the opposite of the tolerance this module promises.
    A line that survives decoding but is not a JSON object is skipped the same
    way, so corruption costs you that record and nothing else.
    """
    try:
        line = raw.decode("utf-8", errors="replace").strip()
    except UnicodeError:  # pragma: no cover - replace never raises, but be sure
        return None
    if not line:
        return None
    try:
        value = json.loads(line)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def iter_records(path: Path) -> Iterator[dict[str, Any]]:
    """Stream audit records one at a time from a JSON Lines file.

    Yields nothing if the file does not exist. Lines that are not valid UTF-8,
    not valid JSON, or not JSON objects are skipped silently, so a single bad
    line never breaks a command.
    """
    if not path.exists():
        return
    # Binary, so that a line which is not valid UTF-8 is one skipped record
    # rather than an exception, and so line endings are never translated.
    with path.open("rb") as handle:
        for raw in handle:
            if (record := parse_line(raw)) is not None:
                yield record


def read_records(path: Path) -> list[dict[str, Any]]:
    """Read all audit records from a JSON Lines file into memory."""
    return list(iter_records(path))


class IncrementalLog:
    """Keeps an audit log in memory, re-reading only what was appended.

    The dashboard polls a log that only ever grows, so re-parsing it in full
    each time makes the cost of asking "what happened lately?" scale with
    everything that ever happened. This reads from where it left off.

    Reading is done in binary and split on newlines before decoding, because a
    poll can land in the middle of a record the writer is still writing — and
    the middle of a record is very often the middle of a multi-byte character.
    Decoding the raw chunk would fail there, on a file that is perfectly fine a
    millisecond later.

    A file that shrank was rotated or truncated, so the cached records are
    dropped and it is read again from the start.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._records: list[dict[str, Any]] = []
        self._position = 0
        self._buffer = b""

    @property
    def path(self) -> Path:
        return self._path

    def records(self) -> list[dict[str, Any]]:
        """Every record in the log, refreshed with whatever has been appended."""
        self._refresh()
        return self._records

    def new_records(self) -> list[dict[str, Any]]:
        """Only what has been appended since the last call.

        Returns everything when the log was rotated or truncated, since the
        caller's accumulated view of it is no longer valid.
        """
        before = len(self._records)
        fresh = self._refresh()
        if len(self._records) < before:  # reset: the file shrank
            return list(self._records)
        return fresh

    def _refresh(self) -> list[dict[str, Any]]:
        """Take in whatever was appended, and return just the new records."""
        try:
            size = self._path.stat().st_size
        except OSError:
            self._reset()
            return []

        if size < self._position:
            self._reset()
        if size == self._position:
            return []

        try:
            with self._path.open("rb") as handle:
                handle.seek(self._position)
                chunk = handle.read()
                self._position = handle.tell()
        except OSError:
            return []

        self._buffer += chunk
        # A trailing fragment is a record still being written; hold it back
        # rather than discarding a line that is about to be complete.
        *lines, self._buffer = self._buffer.split(b"\n")
        fresh = [record for line in lines if (record := parse_line(line)) is not None]
        self._records.extend(fresh)
        return fresh

    def _reset(self) -> None:
        self._records = []
        self._position = 0
        self._buffer = b""


def tail_records(
    path: Path,
    *,
    poll_interval: float = 0.5,
    sleep: Callable[[float], None] = time.sleep,
    should_stop: Callable[[], bool] | None = None,
) -> Iterator[dict[str, Any]]:
    """Follow an audit-log file like ``tail -f``, yielding records as they're appended.

    Starts at the current end of file (so existing records are not replayed).
    If the file does not yet exist, waits for it. Polls every ``poll_interval``
    seconds; ``sleep`` and ``should_stop`` are injectable for tests.
    """
    while not path.exists():
        if should_stop and should_stop():
            return
        sleep(poll_interval)

    position = path.stat().st_size
    buffer = b""
    while True:
        if should_stop and should_stop():
            return
        try:
            # A log that shrank was rotated or truncated out from under us; the
            # saved offset now points past the end of a different file, so start
            # over rather than following nothing forever.
            if path.stat().st_size < position:
                position = 0
                buffer = b""
            with path.open("rb") as handle:
                handle.seek(position)
                chunk = handle.read()
                position = handle.tell()
        except OSError:
            sleep(poll_interval)
            continue
        if not chunk:
            sleep(poll_interval)
            continue
        buffer += chunk
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            if (record := parse_line(line)) is not None:
                yield record

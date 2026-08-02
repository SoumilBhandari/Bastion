"""Reading audit JSON Lines records."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any


def iter_records(path: Path) -> Iterator[dict[str, Any]]:
    """Stream audit records one at a time from a JSON Lines file.

    Yields nothing if the file does not exist. Lines that aren't valid JSON
    or aren't JSON objects are skipped silently — the reader is tolerant of
    log corruption so a single bad line never breaks the CLI.
    """
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                yield value


def read_records(path: Path) -> list[dict[str, Any]]:
    """Read all audit records from a JSON Lines file into memory."""
    return list(iter_records(path))


class IncrementalLog:
    """Keeps an audit log in memory, re-reading only what was appended.

    The dashboard polls a log that only ever grows, so re-parsing it in full
    each time makes the cost of asking "what happened lately?" scale with
    everything that ever happened. This reads from where it left off.

    A file that shrank was rotated or truncated, so the cached records are
    dropped and it is read again from the start.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._records: list[dict[str, Any]] = []
        self._position = 0
        self._buffer = ""

    @property
    def path(self) -> Path:
        return self._path

    def records(self) -> list[dict[str, Any]]:
        """Every record in the log, refreshed with whatever has been appended."""
        self._refresh()
        return self._records

    def _refresh(self) -> None:
        try:
            size = self._path.stat().st_size
        except OSError:
            self._reset()
            return

        if size < self._position:
            self._reset()
        if size == self._position:
            return

        try:
            with self._path.open("r", encoding="utf-8") as handle:
                handle.seek(self._position)
                chunk = handle.read()
                self._position = handle.tell()
        except OSError:
            return

        self._buffer += chunk
        # A trailing fragment is a record still being written; hold it back
        # rather than discarding a line that is about to be complete.
        *lines, self._buffer = self._buffer.split("\n")
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                self._records.append(value)

    def _reset(self) -> None:
        self._records = []
        self._position = 0
        self._buffer = ""


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
    buffer = ""
    while True:
        if should_stop and should_stop():
            return
        try:
            # A log that shrank was rotated or truncated out from under us; the
            # saved offset now points past the end of a different file, so start
            # over rather than following nothing forever.
            if path.stat().st_size < position:
                position = 0
                buffer = ""
            with path.open("r", encoding="utf-8") as handle:
                handle.seek(position)
                chunk = handle.read()
                position = handle.tell()
        except (FileNotFoundError, OSError):
            sleep(poll_interval)
            continue
        if not chunk:
            sleep(poll_interval)
            continue
        buffer += chunk
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            stripped = line.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                yield value

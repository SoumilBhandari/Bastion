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

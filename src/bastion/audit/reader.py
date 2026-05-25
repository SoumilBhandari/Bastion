"""Reading audit JSON Lines records."""

from __future__ import annotations

import json
from collections.abc import Iterator
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

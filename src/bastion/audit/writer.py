"""Append-only JSON Lines writer for audit records."""

from __future__ import annotations

from pathlib import Path

from bastion.audit.record import AuditRecord


class AuditWriter:
    """Appends audit records to a JSON Lines file — one record per line."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def write(self, record: AuditRecord) -> None:
        """Append one audit record to the log file."""
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(record.to_json_line() + "\n")

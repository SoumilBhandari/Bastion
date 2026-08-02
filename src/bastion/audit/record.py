"""The audit record — one structured entry per governed operation."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def _new_call_id() -> str:
    return uuid.uuid4().hex


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class AuditRecord:
    """One audit-log entry, serialized as a single JSON line.

    Created when an operation starts; ``outcome``, ``duration_ms``, and
    ``error`` are filled in once it completes.
    """

    tool: str
    kind: str = "tool"
    arguments: dict[str, Any] | None = None
    call_id: str = field(default_factory=_new_call_id)
    timestamp: str = field(default_factory=_now_iso)
    outcome: str = "ok"
    duration_ms: float = 0.0
    error: str | None = None
    cost: float | None = None
    flags: list[str] | None = None

    def payload(self) -> dict[str, Any]:
        """The record's own fields, without any hash-chain metadata."""
        return {
            "call_id": self.call_id,
            "timestamp": self.timestamp,
            "tool": self.tool,
            "kind": self.kind,
            "arguments": self.arguments,
            "outcome": self.outcome,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "cost": self.cost,
            "flags": self.flags,
        }

    def to_json_line(self) -> str:
        """Serialize to a single-line JSON string (no trailing newline)."""
        return json.dumps(self.payload(), default=str, ensure_ascii=False)

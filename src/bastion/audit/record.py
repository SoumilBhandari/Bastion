"""The audit record — one structured entry per tool call."""

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

    Created when a tool call starts; ``outcome``, ``duration_ms``, and ``error``
    are filled in once the call completes.
    """

    tool: str
    arguments: dict[str, Any] | None = None
    call_id: str = field(default_factory=_new_call_id)
    timestamp: str = field(default_factory=_now_iso)
    outcome: str = "ok"
    duration_ms: float = 0.0
    error: str | None = None

    def to_json_line(self) -> str:
        """Serialize to a single-line JSON string (no trailing newline)."""
        payload: dict[str, Any] = {
            "call_id": self.call_id,
            "timestamp": self.timestamp,
            "tool": self.tool,
            "arguments": self.arguments,
            "outcome": self.outcome,
            "duration_ms": self.duration_ms,
            "error": self.error,
        }
        return json.dumps(payload, default=str, ensure_ascii=False)

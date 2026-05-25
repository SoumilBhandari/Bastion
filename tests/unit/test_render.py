"""Unit tests for the audit-log render helpers."""

from __future__ import annotations

from io import StringIO
from typing import Any

from rich.console import Console

from bastion.viewer.render import (
    format_record_line,
    render_records_table,
    render_stats,
    shorten_timestamp,
    style_outcome,
)


def _render(fn: Any, *args: Any, **kwargs: Any) -> str:
    out = StringIO()
    console = Console(file=out, force_terminal=False, width=160)
    fn(*args, **kwargs, console=console)
    return out.getvalue()


def test_shorten_timestamp_returns_hms() -> None:
    assert shorten_timestamp("2026-05-25T14:30:45.123Z") == "14:30:45"


def test_shorten_timestamp_passes_short_strings_through() -> None:
    assert shorten_timestamp("short") == "short"


def test_style_outcome_known_values() -> None:
    assert "green" in style_outcome("ok")
    assert "yellow" in style_outcome("denied")
    assert "red" in style_outcome("error")


def test_style_outcome_unknown_value_passes_through() -> None:
    assert style_outcome("weird") == "weird"


def test_render_records_table_empty_shows_placeholder() -> None:
    assert "no audit records" in _render(render_records_table, [])


def test_render_records_table_includes_record_fields() -> None:
    output = _render(
        render_records_table,
        [
            {
                "timestamp": "2026-05-25T14:30:45.123Z",
                "tool": "echo",
                "outcome": "ok",
                "duration_ms": 1.5,
            }
        ],
    )
    assert "14:30:45" in output
    assert "echo" in output
    assert "ok" in output
    assert "1.5ms" in output


def test_render_stats_empty_shows_placeholder() -> None:
    assert "no audit records" in _render(render_stats, [])


def test_render_stats_includes_totals_and_top_tools() -> None:
    records = [
        {"tool": "echo", "outcome": "ok", "duration_ms": 2.0},
        {"tool": "echo", "outcome": "ok", "duration_ms": 4.0},
        {"tool": "echo", "outcome": "ok", "duration_ms": 6.0},
        {"tool": "delete", "outcome": "denied", "duration_ms": 1.0},
    ]
    output = _render(render_stats, records)
    assert "4 audit records" in output
    assert "echo" in output and "3" in output  # echo appeared 3x
    assert "delete" in output and "denied" in output


def test_format_record_line_includes_key_fields() -> None:
    line = format_record_line(
        {
            "timestamp": "2026-05-25T14:30:45.123Z",
            "tool": "echo",
            "outcome": "ok",
            "duration_ms": 1.5,
        }
    )
    assert "14:30:45" in line
    assert "echo" in line
    assert "1.5ms" in line


def test_format_record_line_includes_error_when_present() -> None:
    line = format_record_line(
        {
            "timestamp": "2026-05-25T14:30:45Z",
            "tool": "boom",
            "outcome": "error",
            "duration_ms": 0.1,
            "error": "kaboom",
        }
    )
    assert "boom" in line
    assert "kaboom" in line

"""Rendering helpers for the audit log viewer commands."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from typing import Any

from rich.console import Console
from rich.table import Table

_OUTCOME_STYLES = {
    "ok": "[green]ok[/green]",
    "denied": "[yellow]denied[/yellow]",
    "error": "[red]error[/red]",
}


def style_outcome(outcome: str) -> str:
    """Return a rich-formatted version of an audit outcome string."""
    return _OUTCOME_STYLES.get(outcome, outcome)


def shorten_timestamp(ts: str) -> str:
    """Trim an ISO 8601 timestamp to ``HH:MM:SS``."""
    return ts[11:19] if len(ts) >= 19 else ts


def render_records_table(
    records: Sequence[dict[str, Any]],
    console: Console | None = None,
) -> None:
    """Pretty-print a list of audit records as a table."""
    console = console or Console()
    if not records:
        console.print("[dim]no audit records[/dim]")
        return
    table = Table(show_lines=False, header_style="bold")
    table.add_column("Time", style="dim", no_wrap=True)
    table.add_column("Tool")
    table.add_column("Outcome")
    table.add_column("Duration", justify="right")
    table.add_column("Error", overflow="fold")
    for record in records:
        table.add_row(
            shorten_timestamp(str(record.get("timestamp", ""))),
            str(record.get("tool", "")),
            style_outcome(str(record.get("outcome", ""))),
            f"{float(record.get('duration_ms', 0)):.1f}ms",
            str(record.get("error") or ""),
        )
    console.print(table)


def render_stats(
    records: Sequence[dict[str, Any]],
    console: Console | None = None,
    *,
    top: int = 5,
) -> None:
    """Print a one-shot summary of the audit log: totals, outcomes, top tools."""
    console = console or Console()
    total = len(records)
    if total == 0:
        console.print("[dim]no audit records[/dim]")
        return

    outcomes: Counter[str] = Counter(str(r.get("outcome", "")) for r in records)
    tools: Counter[str] = Counter(str(r.get("tool", "")) for r in records)
    avg_ms = sum(float(r.get("duration_ms", 0)) for r in records) / total

    console.print(f"[bold]{total}[/bold] audit records · avg [bold]{avg_ms:.1f}ms[/bold]")
    console.print("")

    outcome_table = Table(title="Outcomes", show_header=True, header_style="bold")
    outcome_table.add_column("Outcome")
    outcome_table.add_column("Count", justify="right")
    for outcome, count in outcomes.most_common():
        outcome_table.add_row(style_outcome(outcome), str(count))
    console.print(outcome_table)

    tool_table = Table(
        title=f"Top {min(top, len(tools))} tools", show_header=True, header_style="bold"
    )
    tool_table.add_column("Tool")
    tool_table.add_column("Calls", justify="right")
    for tool, count in tools.most_common(top):
        tool_table.add_row(tool, str(count))
    console.print(tool_table)

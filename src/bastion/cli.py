"""The bastion command-line interface."""

import fnmatch
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from bastion import __version__
from bastion.audit import read_records, tail_records
from bastion.config import BastionConfig, ConfigError, find_config, load_config
from bastion.dashboard import run_dashboard
from bastion.gateway import build_gateway
from bastion.viewer import format_record_line, render_records_table, render_stats

app = typer.Typer(
    name="bastion",
    help="A local-first control plane for your AI agent's tools.",
    no_args_is_help=True,
    add_completion=False,
)

ConfigOption = Annotated[
    Path | None,
    typer.Option("--config", "-c", help="Path to bastion.yaml (default: ./bastion.yaml)."),
]


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"bastion {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            callback=_version_callback,
            help="Print the bastion version.",
            is_eager=True,
        ),
    ] = None,
) -> None:
    """A local-first control plane for your AI agent's tools."""


def _load(config: Path | None) -> BastionConfig:
    """Locate and load the config, exiting cleanly on any configuration error."""
    try:
        return load_config(find_config(config))
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command()
def run(config: ConfigOption = None) -> None:
    """Run the gateway, proxying every configured upstream MCP server."""
    cfg = _load(config)
    gateway = build_gateway(cfg)
    settings = cfg.gateway
    if settings.transport == "http":
        gateway.run(transport="http", host=settings.host, port=settings.port, show_banner=False)
    else:
        gateway.run(transport="stdio", show_banner=False)


@app.command()
def dashboard(
    config: ConfigOption = None,
    host: Annotated[str, typer.Option(help="Host to bind the dashboard to.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port to serve the dashboard on.")] = 8787,
) -> None:
    """Serve a local web dashboard that visualizes the audit log."""
    cfg = _load(config)
    typer.echo(f"Bastion dashboard -> http://{host}:{port}")
    typer.echo(f"(reading audit log: {cfg.audit.path})")
    run_dashboard(cfg, host=host, port=port)


@app.command()
def validate(config: ConfigOption = None) -> None:
    """Validate the configuration file and report any problems."""
    cfg = _load(config)
    count = len(cfg.upstreams)
    plural = "" if count == 1 else "s"
    typer.echo(f"OK - configuration is valid ({count} upstream{plural}).")


@app.command()
def logs(
    config: ConfigOption = None,
    tool: Annotated[
        str | None,
        typer.Option(help="Only show records for tools matching this glob."),
    ] = None,
    outcome: Annotated[
        str | None,
        typer.Option(help="Only show records with this outcome (ok/error/denied)."),
    ] = None,
    limit: Annotated[
        int | None,
        typer.Option("-n", "--limit", help="Show only the last N records."),
    ] = None,
) -> None:
    """Show past audit-log records (most recent last)."""
    cfg = _load(config)
    records = read_records(cfg.audit.path)
    if tool:
        records = [r for r in records if fnmatch.fnmatch(str(r.get("tool", "")), tool)]
    if outcome:
        records = [r for r in records if r.get("outcome") == outcome]
    if limit and limit > 0:
        records = records[-limit:]
    render_records_table(records)


@app.command()
def tail(config: ConfigOption = None) -> None:
    """Follow the audit log, printing new records as they're recorded (Ctrl+C to exit)."""
    cfg = _load(config)
    console = Console()
    console.print(f"[dim]tailing {cfg.audit.path} (Ctrl+C to exit)[/dim]")
    try:
        for record in tail_records(cfg.audit.path):
            console.print(format_record_line(record))
    except KeyboardInterrupt:
        console.print("\n[dim]stopped[/dim]")


STARTER_CONFIG = """\
# Bastion configuration. Run with:  bastion run
#
# See docs/configuration.md and examples/ for reference and more involved configs.

upstreams:
  files:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "."]

audit:
  enabled: true
  path: ./bastion-audit.jsonl

policy:
  default: allow
  permissions:
    # Most-specific rule wins; broader rules come first.
    - { tool: "files_read_*",   action: allow }
    - { tool: "files_delete_*", action: deny  }
"""


@app.command()
def init(
    path: Annotated[
        Path, typer.Option(help="Where to write the new config.")
    ] = Path("bastion.yaml"),
    force: Annotated[
        bool, typer.Option(help="Overwrite if the file already exists.")
    ] = False,
) -> None:
    """Scaffold a starter bastion.yaml."""
    if path.exists() and not force:
        typer.echo(f"error: {path} already exists (use --force to overwrite)", err=True)
        raise typer.Exit(code=1)
    path.write_text(STARTER_CONFIG, encoding="utf-8")
    typer.echo(f"wrote {path}")


@app.command()
def stats(config: ConfigOption = None) -> None:
    """Print a summary of the audit log: totals, outcomes, and top tools."""
    cfg = _load(config)
    records = read_records(cfg.audit.path)
    render_stats(records)


@app.command()
def version() -> None:
    """Print the bastion version."""
    typer.echo(f"bastion {__version__}")

"""The bastion command-line interface."""

from pathlib import Path
from typing import Annotated

import typer

from bastion import __version__
from bastion.config import BastionConfig, ConfigError, find_config, load_config
from bastion.dashboard import run_dashboard
from bastion.gateway import build_gateway

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
def version() -> None:
    """Print the bastion version."""
    typer.echo(f"bastion {__version__}")

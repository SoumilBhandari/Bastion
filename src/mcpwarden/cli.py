"""The mcpwarden command-line interface."""

from pathlib import Path
from typing import Annotated

import typer

from mcpwarden import __version__
from mcpwarden.config import ConfigError, WardenConfig, find_config, load_config
from mcpwarden.gateway import build_gateway

app = typer.Typer(
    name="mcpwarden",
    help="A local-first control plane for your AI agent's tools.",
    no_args_is_help=True,
    add_completion=False,
)

ConfigOption = Annotated[
    Path | None,
    typer.Option("--config", "-c", help="Path to mcpwarden.yaml (default: ./mcpwarden.yaml)."),
]


def _load(config: Path | None) -> WardenConfig:
    """Locate and load the config, exiting cleanly on any configuration error."""
    try:
        return load_config(find_config(config))
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command()
def run(config: ConfigOption = None) -> None:
    """Run the gateway, proxying every configured upstream MCP server."""
    warden_config = _load(config)
    gateway = build_gateway(warden_config)
    settings = warden_config.gateway
    if settings.transport == "http":
        gateway.run(transport="http", host=settings.host, port=settings.port, show_banner=False)
    else:
        gateway.run(transport="stdio", show_banner=False)


@app.command()
def validate(config: ConfigOption = None) -> None:
    """Validate the configuration file and report any problems."""
    warden_config = _load(config)
    count = len(warden_config.upstreams)
    plural = "" if count == 1 else "s"
    typer.echo(f"OK - configuration is valid ({count} upstream{plural}).")


@app.command()
def version() -> None:
    """Print the mcpwarden version."""
    typer.echo(f"mcpwarden {__version__}")

"""The bastion command-line interface."""

import asyncio
import fnmatch
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.table import Table

from bastion import __version__
from bastion.audit import iter_records, read_records, rotated_paths, tail_records, verify_records
from bastion.config import BastionConfig, ConfigError, find_config, load_config
from bastion.console import build as build_console
from bastion.console import marks_for
from bastion.dashboard import new_token, run_dashboard
from bastion.gateway import build_gateway
from bastion.gateway.app import build_mcp_config
from bastion.policy import PolicyEngine
from bastion.policy.pinning import PinChecker, PinStore, ToolFingerprint
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


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def _warn_if_exposed(host: str, what: str) -> None:
    """Warn when binding ``what`` to a non-loopback host (unauthenticated exposure)."""
    if host not in _LOOPBACK_HOSTS:
        typer.echo(
            f"warning: binding {what} to {host} exposes it to the network with no "
            "authentication; keep it on localhost or front it with an authenticating proxy.",
            err=True,
        )


@app.command()
def run(config: ConfigOption = None) -> None:
    """Run the gateway, proxying every configured upstream MCP server."""
    cfg = _load(config)
    gateway = build_gateway(cfg)
    settings = cfg.gateway
    if settings.transport == "http":
        _warn_if_exposed(settings.host, "the gateway")
        gateway.run(transport="http", host=settings.host, port=settings.port, show_banner=False)
    else:
        gateway.run(transport="stdio", show_banner=False)


@app.command()
def dashboard(
    config: ConfigOption = None,
    host: Annotated[str, typer.Option(help="Host to bind the dashboard to.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port to serve the dashboard on.")] = 8787,
    no_token: Annotated[
        bool,
        typer.Option(
            "--no-token",
            help="Serve without an access token (only behind your own authenticating proxy).",
        ),
    ] = False,
) -> None:
    """Serve a local web dashboard that visualizes the audit log."""
    cfg = _load(config)
    _warn_if_exposed(host, "the dashboard")
    token = None if no_token else new_token()
    suffix = f"/?t={token}" if token else "/"
    typer.echo(f"Bastion dashboard -> http://{host}:{port}{suffix}")
    typer.echo(f"(reading audit log: {cfg.audit.path})")
    if token is None:
        typer.echo(
            "warning: serving the audit log with no access token; anything that can "
            "reach this port can read every argument your agent passed.",
            err=True,
        )
    run_dashboard(cfg, host=host, port=port, token=token)


@app.command()
def validate(config: ConfigOption = None) -> None:
    """Validate the configuration file and report any problems."""
    cfg = _load(config)
    count = len(cfg.upstreams)
    plural = "" if count == 1 else "s"
    typer.echo(f"OK - configuration is valid ({count} upstream{plural}).")


@app.command()
def explain(
    tool: Annotated[str, typer.Argument(help="The tool name to evaluate policy for.")],
    config: ConfigOption = None,
    args: Annotated[
        str | None,
        typer.Option("--args", help='Arguments as JSON, e.g. \'{"path": "/etc/passwd"}\'.'),
    ] = None,
) -> None:
    """Show exactly what policy would do with a call, and why.

    Every layer is evaluated, not just the first one to refuse, so a call
    blocked by several rules at once shows all of them. Nothing is consumed:
    rate-limit tokens and budget counters are read, never spent.
    """
    cfg = _load(config)

    arguments: dict[str, Any] | None = None
    if args is not None:
        try:
            parsed = json.loads(args)
        except json.JSONDecodeError as exc:
            typer.echo(f"error: --args is not valid JSON: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        if not isinstance(parsed, dict):
            typer.echo("error: --args must be a JSON object", err=True)
            raise typer.Exit(code=1)
        arguments = parsed

    engine = PolicyEngine(cfg.policy, cost=cfg.cost)
    result = engine.explain(tool, arguments)
    console = build_console()
    marks = marks_for()

    verdict = "[green]ALLOWED[/green]" if result.allowed else "[red]DENIED[/red]"
    console.print(f"{verdict}  [bold]{tool}[/bold]")
    console.print()

    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("")
    table.add_column("Layer")
    table.add_column("Detail", overflow="fold")
    for step in result.steps:
        if step.skipped:
            mark = f"[dim]{marks.skip}[/dim]"
        else:
            mark = f"[green]{marks.ok}[/green]" if step.allowed else f"[red]{marks.bad}[/red]"
        table.add_row(mark, step.layer, f"[dim]{step.detail}[/dim]")
    console.print(table)

    console.print()
    console.print(f"[dim]cost per call:[/dim] {result.cost:g}")
    timeout = cfg.timeouts.for_tool(tool)
    console.print(f"[dim]timeout:[/dim] {f'{timeout:g}s' if timeout else 'none'}")
    listed = result.steps[0].allowed or not cfg.policy.hide_denied
    console.print(f"[dim]visible in tools/list:[/dim] {'yes' if listed else 'no'}")

    if not result.allowed:
        raise typer.Exit(code=1)


@app.command()
def doctor(config: ConfigOption = None) -> None:
    """Check the configuration, the upstreams, and the audit log for problems."""
    cfg = _load(config)
    console = build_console()
    marks = marks_for()
    problems = 0

    console.print(f"[bold]config[/bold]  {find_config(config)}")
    console.print(f"  [green]{marks.ok}[/green] valid — {len(cfg.upstreams)} upstream(s)")

    console.print("\n[bold]upstreams[/bold]")
    probes = asyncio.run(_probe_upstreams(cfg))
    for probe in probes:
        if probe.reachable:
            console.print(f"  [green]{marks.ok}[/green] {probe.name} — {probe.detail}")
        else:
            problems += 1
            console.print(f"  [red]{marks.bad}[/red] {probe.name} — {probe.detail}")

    advertised = sorted({tool for probe in probes for tool in probe.tools})
    if advertised:
        console.print("\n[bold]rules[/bold]")
        idle = _rules_matching_nothing(cfg, advertised)
        if not idle:
            console.print(
                f"  [green]{marks.ok}[/green] every rule matches at least one of "
                f"{len(advertised)} advertised tools"
            )
        for note in idle:
            problems += 1
            console.print(f"  [red]{marks.bad}[/red] {note}")

    console.print("\n[bold]audit log[/bold]")
    if not cfg.audit.enabled:
        console.print("  [yellow]![/yellow] disabled — nothing your agent does is recorded")
    elif not cfg.audit.path.exists():
        console.print(f"  [dim]{marks.skip}[/dim] {cfg.audit.path} does not exist yet")
    else:
        report = verify_records(read_records(cfg.audit.path))
        if not report.ok:
            problems += 1
            console.print(f"  [red]{marks.bad}[/red] chain broken at {report.breaks[0]}")
        elif not report.starts_at_genesis and not rotated_paths(cfg.audit.path):
            problems += 1
            console.print(
                f"  [red]{marks.bad}[/red] the chain does not start at its beginning and nothing "
                "was rotated — records were removed from the front of the log"
            )
        else:
            console.print(f"  [green]{marks.ok}[/green] {report.checked} records, chain intact")
            if report.unchained:
                console.print(
                    f"  [yellow]![/yellow] {report.unchained} record(s) carry no hash and "
                    "were not verified"
                )

    console.print("\n[bold]advice[/bold]")
    advice = _review_settings(cfg)
    if not advice:
        console.print(f"  [green]{marks.ok}[/green] nothing to flag")
    for note in advice:
        console.print(f"  [yellow]![/yellow] {note}")

    if problems:
        raise typer.Exit(code=1)


@dataclass(frozen=True)
class UpstreamProbe:
    """What one upstream said when `bastion doctor` connected to it."""

    name: str
    reachable: bool
    detail: str
    tools: tuple[str, ...] = ()


async def _probe_upstreams(cfg: BastionConfig) -> list[UpstreamProbe]:
    """Connect to each upstream on its own and report what it advertises."""
    from fastmcp import Client
    from fastmcp.server import create_proxy

    from bastion.gateway.app import _upstream_to_mcp_server

    results: list[UpstreamProbe] = []
    multiple = len(cfg.upstreams) > 1
    for name, upstream in cfg.upstreams.items():
        single = {"mcpServers": {name: _upstream_to_mcp_server(upstream)}}
        started = time.monotonic()
        try:
            async with Client(create_proxy(single, name="bastion-doctor")) as client:
                tools = await client.list_tools()
            elapsed = (time.monotonic() - started) * 1000
            # Probed one at a time, so no namespace prefix is applied here; the
            # gateway only adds one when several upstreams are configured.
            names = tuple(f"{name}_{tool.name}" if multiple else tool.name for tool in tools)
            results.append(
                UpstreamProbe(
                    name, True, f"{len(tools)} tools, connected in {elapsed:.0f}ms", names
                )
            )
        except Exception as exc:
            results.append(UpstreamProbe(name, False, f"unreachable: {type(exc).__name__}: {exc}"))
    return results


def _rules_matching_nothing(cfg: BastionConfig, advertised: list[str]) -> list[str]:
    """Rules whose glob matches none of the tools the upstreams actually expose.

    A rule matching nothing is nearly always a name that does not exist — most
    often carrying the namespace prefix, which the gateway adds only when
    several upstreams are configured. Such a rule is silently inert: a deny that
    never denies, or an allowlist entry that leaves default-deny blocking
    everything. Nothing at config-validation time can tell that from a rule kept
    deliberately for a tool that is simply not connected today, which is exactly
    why it is worth saying out loud here, where the real tool names are known.
    """
    notes: list[str] = []
    for rule in cfg.policy.permissions:
        if not fnmatch.filter(advertised, rule.tool):
            notes.append(
                f"permission rule '{rule.tool}' ({rule.action}) matches none of the "
                "advertised tools — it can never take effect"
            )
    for guard in cfg.policy.guards:
        if not fnmatch.filter(advertised, guard.match):
            notes.append(
                f"guard '{guard.name}' applies to '{guard.match}', which matches none of "
                "the advertised tools"
            )
    for response_guard in cfg.policy.responses.guards:
        if not fnmatch.filter(advertised, response_guard.match):
            notes.append(
                f"response guard '{response_guard.name}' applies to "
                f"'{response_guard.match}', which matches none of the advertised tools"
            )
    return notes


def _review_settings(cfg: BastionConfig) -> list[str]:
    """Flag configurations that are legal but probably not what was intended."""
    notes: list[str] = []
    policy = cfg.policy

    if policy.default == "allow" and not policy.permissions:
        notes.append(
            "policy.default is 'allow' with no permission rules — every tool on every "
            "upstream is reachable. Consider default: deny with an allowlist."
        )
    if not policy.budgets and not policy.rate_limits:
        notes.append("no rate limits and no budgets — a looping agent has nothing to stop it.")

    # A spend cap charges against the cost model, which defaults to zero. Left
    # at the default, the cap is real, configured, visible in the file — and can
    # never be reached, because every call costs nothing.
    spend_caps = [rule.name for rule in policy.budgets if rule.max_cost is not None]
    priced = cfg.cost.default_per_call > 0 or any(cost > 0 for cost in cfg.cost.per_tool.values())
    if spend_caps and not priced:
        listed = ", ".join(f"'{name}'" for name in spend_caps)
        notes.append(
            f"budget {listed} caps spend, but every call costs 0 — set cost.default_per_call "
            "or cost.per_tool, or the cap can never be reached."
        )
    if cfg.audit.enabled and not cfg.audit.log_arguments:
        notes.append(
            "audit.log_arguments is off, so the log records that a tool ran but not "
            "what it was asked to do. audit.redact_secrets already keeps credentials out."
        )
    if cfg.audit.enabled and not cfg.audit.hash_chain:
        notes.append("audit.hash_chain is off — edits to the audit log are undetectable.")
    if not policy.pinning.enabled:
        notes.append(
            "policy.pinning is off — an upstream can change a tool's description, and "
            "the agent will follow the new instructions."
        )
    if cfg.timeouts.default_seconds is None:
        notes.append("timeouts.default_seconds is null — a wedged upstream will hang the agent.")
    if cfg.gateway.transport == "http" and cfg.gateway.host not in _LOOPBACK_HOSTS:
        notes.append(
            f"the gateway binds to {cfg.gateway.host} with no authentication — anyone who "
            "can reach it can drive your tools."
        )
    return notes


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
    console = build_console()
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
    #
    # These names are unprefixed because there is a single upstream above. Add a
    # second and every tool becomes <upstream>_<tool>, so the rules need the
    # prefix too. `bastion doctor` reports any rule that matches nothing.
    - { tool: "read_*",     action: allow }
    - { tool: "write_file", action: deny  }
"""


@app.command()
def init(
    path: Annotated[Path, typer.Option(help="Where to write the new config.")] = Path(
        "bastion.yaml"
    ),
    force: Annotated[bool, typer.Option(help="Overwrite if the file already exists.")] = False,
) -> None:
    """Scaffold a starter bastion.yaml."""
    if path.exists() and not force:
        typer.echo(f"error: {path} already exists (use --force to overwrite)", err=True)
        raise typer.Exit(code=1)
    try:
        # Create the directory the caller named rather than refusing: they asked
        # for the file to be there. Anything else — a read-only volume, a path
        # component that is a file — is reported, not raised as a traceback.
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(STARTER_CONFIG, encoding="utf-8")
    except OSError as exc:
        typer.echo(f"error: cannot write {path}: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"wrote {path}")


@app.command()
def pin(
    config: ConfigOption = None,
    approve: Annotated[
        bool,
        typer.Option("--approve", help="Accept the current definitions, replacing the pins."),
    ] = False,
) -> None:
    """Show tool definitions that changed since they were pinned, and re-approve them.

    Connects to every configured upstream, fingerprints what it advertises, and
    compares that against the pin file. Without --approve this only reports.
    """
    cfg = _load(config)
    console = build_console()
    store = PinStore(cfg.policy.pinning.path)

    try:
        fingerprints = asyncio.run(_live_fingerprints(cfg))
    except Exception as exc:
        typer.echo(f"error: could not reach the upstreams: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if approve:
        store.replace_all(fingerprints)
        store.save()
        console.print(f"[green]pinned[/green] {len(fingerprints)} tool definitions to {store.path}")
        return

    report = PinChecker(store).check(fingerprints)
    if report.newly_pinned:
        console.print(f"[dim]newly pinned:[/dim] {', '.join(sorted(report.newly_pinned))}")
    if report.ok:
        console.print(f"[green]OK[/green] — {report.unchanged} tool definitions match their pins.")
        return

    console.print(
        f"[yellow]{len(report.drifted)} tool definition(s) changed since pinning:[/yellow]"
    )
    for drift in report.drifted:
        console.print(f"\n  [yellow]·[/yellow] {drift.summary()}")
        if drift.description_changed:
            console.print(f"      [dim]pinned :[/dim] {_preview(drift.pinned_description)}")
            console.print(f"      [dim]current:[/dim] {_preview(drift.current_description)}")
    console.print(
        "\n[dim]Review each change before accepting it — a tool description is an "
        "instruction the agent will follow. Re-approve with `bastion pin --approve`.[/dim]"
    )
    raise typer.Exit(code=1)


def _preview(text: str, limit: int = 160) -> str:
    collapsed = " ".join(text.split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 1] + "…"


async def _live_fingerprints(cfg: BastionConfig) -> list[ToolFingerprint]:
    """Fingerprint every tool the configured upstreams currently advertise.

    Talks to a bare proxy rather than the full gateway, so policy filtering
    cannot hide a tool whose definition is exactly what we came to inspect.
    """
    from fastmcp import Client
    from fastmcp.server import create_proxy

    proxy = create_proxy(build_mcp_config(cfg), name="bastion-pin")
    async with Client(proxy) as client:
        tools = await client.list_tools()
    return [ToolFingerprint.of(tool) for tool in tools]


@app.command()
def verify(
    config: ConfigOption = None,
    include_rotated: Annotated[
        bool,
        typer.Option(
            "--include-rotated",
            help="Also verify rotated generations, oldest first, as one chain.",
        ),
    ] = False,
) -> None:
    """Check the audit log's hash chain for signs of tampering."""
    cfg = _load(config)
    path = cfg.audit.path
    sources = [*rotated_paths(path), path] if include_rotated else [path]

    records: list[dict[str, object]] = []
    for source in sources:
        records.extend(iter_records(source))

    if not records:
        typer.echo(f"no audit records in {path}")
        return

    report = verify_records(records)

    # A chain that does not open at genesis is missing its beginning. Rotation
    # explains that; nothing else does. Treating it as merely informational let
    # deleting the front of a log pass as "OK", which is precisely the edit
    # someone covering their tracks would make.
    unexplained_start = not report.starts_at_genesis and not rotated_paths(path)
    failed = not report.ok or unexplained_start
    console = build_console(stderr=failed)

    if not report.ok:
        console.print(f"[red]FAILED[/red] — the audit log at {path} does not verify:")
        for entry in report.breaks:
            console.print(f"  [red]·[/red] {entry}")
        console.print(
            "\n[dim]Everything before the first break is intact. Records after it "
            "cannot be trusted.[/dim]"
        )
        raise typer.Exit(code=1)

    if unexplained_start:
        console.print(
            f"[red]FAILED[/red] — the chain in {path} does not start at its beginning, and "
            "there are no rotated generations to account for it. Records were removed "
            "from the front of the log."
        )
        raise typer.Exit(code=1)

    console.print(f"[green]OK[/green] — {report.checked} records form an unbroken chain.")
    if report.unchained:
        console.print(
            f"[dim]{report.unchained} earlier record(s) predate hash chaining and were "
            "not verified.[/dim]"
        )
    if not report.starts_at_genesis and not include_rotated:
        console.print(
            "[dim]The chain continues from an earlier generation; pass --include-rotated "
            "to verify from the beginning.[/dim]"
        )
    if report.head:
        console.print(f"[dim]head:[/dim] {report.head}")


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

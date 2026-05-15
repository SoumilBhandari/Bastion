# mcpwarden

**A local-first control plane for your AI agent's tools.** mcpwarden is a gateway
that sits between an AI agent (Claude Code, Cursor, Claude Desktop, …) and the
MCP servers it uses — capping spend, rate-limiting, enforcing per-action
permissions, and auditing every tool call.

> **Status: early development.** mcpwarden is being built in the open, milestone
> by milestone. Today it works as a transparent multi-upstream MCP proxy with
> config validation; policy enforcement (permissions, rate limits, budgets,
> argument guards) and the audit log land over the next milestones — see the
> [roadmap](#roadmap).

## Why

[Model Context Protocol](https://modelcontextprotocol.io) won — every major AI
vendor ships it and there are 17,000+ MCP servers. But agents call those servers
with **no spend caps, no rate limits, no permissions, and no audit trail**. A
looping agent can burn real money in minutes, and you have no record of what it
did.

mcpwarden is the missing control layer. One config file, one command, no cloud,
no database.

## How it works

Your agent points at mcpwarden instead of at its MCP servers directly. mcpwarden
is both an MCP server (to the agent) and an MCP client (to the real "upstream"
servers). It aggregates your upstreams behind one endpoint and — as policy
features land — enforces rules on every `tools/call`:

```
  AI agent  ──MCP──▶  mcpwarden  ──MCP──▶  upstream server A
                      (policy +           upstream server B
                       audit)             upstream server C
```

## Install

Not yet on PyPI. For now, install from source:

```bash
git clone https://github.com/SoumilBhandari/mcpwarden
cd mcpwarden
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -e .
```

## Quickstart

Create `mcpwarden.yaml`:

```yaml
upstreams:
  files:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/project"]
```

Validate it:

```bash
mcpwarden validate
```

Point your agent at the gateway — e.g. for Claude Code:

```bash
claude mcp add --transport stdio mcpwarden -- mcpwarden run --config ./mcpwarden.yaml
```

Your agent now reaches the filesystem server *through* mcpwarden. Each upstream's
tools are namespaced by its config key — the `files` upstream above exposes
`files_read_file`, `files_write_file`, and so on.

## Configuration

`mcpwarden.yaml` — `upstreams` is required; everything else is optional.

```yaml
gateway:
  transport: stdio          # stdio | http

upstreams:                  # key = namespace prefix for that server's tools
  files:
    command: npx            # `command` ⇒ stdio upstream
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
  search:
    url: https://search.example.com/mcp   # `url` ⇒ http upstream
```

Policy sections (`policy`, `audit`, `cost`) are documented as they land — see
the roadmap below.

## Roadmap

mcpwarden is built in milestones; each adds one capability:

- [x] **M0** — multi-upstream proxy (stdio + HTTP), config schema, CLI
- [ ] **M1** — audit log: every tool call recorded to JSONL
- [ ] **M2** — permissions: per-tool allow/deny rules
- [ ] **M3** — rate limiting: per-tool / per-client / global token buckets
- [ ] **M4** — budgets: call-count and cost caps that survive restarts
- [ ] **M5** — argument guards: block dangerous tool arguments
- [ ] **M6** — live log viewer (`mcpwarden tail`) and CLI polish
- [ ] **M7** — docs, examples, `v0.1.0` release on PyPI

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache 2.0](LICENSE)
